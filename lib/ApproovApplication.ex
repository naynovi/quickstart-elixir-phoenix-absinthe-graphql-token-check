defmodule ApproovApplication.Application do
  use Application

  def start(_type, _args) do
    children = [
      ApproovApplication.State,
      ApproovApplication.Endpoint
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: ApproovApplication.Supervisor)
  end
end

defmodule ApproovApplication.State do
  use Agent

  @initial_state %{approov_enabled: true, token_binding_enabled: true}

  def start_link(_opts) do
    Agent.start_link(fn -> @initial_state end, name: __MODULE__)
  end

  def approov_enabled? do
    Agent.get(__MODULE__, & &1.approov_enabled)
  end

  def token_binding_enabled? do
    Agent.get(__MODULE__, & &1.token_binding_enabled)
  end

  def enable_approov do
    Agent.update(__MODULE__, fn _ -> @initial_state end)
  end

  def disable_approov do
    Agent.update(__MODULE__, fn _ -> %{approov_enabled: false, token_binding_enabled: false} end)
  end

  def enable_binding do
    Agent.update(__MODULE__, fn state -> %{state | token_binding_enabled: true} end)
  end

  def disable_binding do
    Agent.update(__MODULE__, fn state -> %{state | token_binding_enabled: false} end)
  end

  def state_payload do
    %{
      approovEnabled: approov_enabled?(),
      tokenBindingEnabled: token_binding_enabled?()
    }
  end

  def info_payload(details) when is_binary(details) do
    state_payload()
    |> Map.put(:details, details)
  end
end

defmodule ApproovApplication.ProtectedRoutes do
  @moduledoc false

  # Protected route levels (token-only vs token+binding). These levels are used
  # by the middleware to decide which checks and bindings apply per endpoint.
  @protected_route_levels %{
    "/token-check" => %{approov: :required, binding_headers: []},
    "/token-binding" => %{approov: :required, binding_headers: ["authorization"]},
    "/token-double-binding" =>
      %{approov: :required, binding_headers: ["authorization", "content-digest"]}
  }

  def levels, do: @protected_route_levels

  def binding_headers_for_path(path) when is_binary(path) do
    case Map.get(@protected_route_levels, path) do
      %{binding_headers: headers} when is_list(headers) -> headers
      _ -> []
    end
  end
end

defmodule ApproovApplication.ApproovToken do
  @moduledoc false
  require Logger

  use Joken.Config

  @approov_header "approov-token"

  @impl Joken.Config
  def token_config do
    default_claims(skip: [:aud, :iat, :iss, :jti, :nbf])
  end

  # Verifies the Approov token (signature + expiry) and returns its claims.
  def verify_token(%Plug.Conn{} = conn) do
    with {:ok, token} <- fetch_token(conn),
         {:ok, claims} <- decode_and_verify(token) do
      {:ok, claims}
    else
      {:error, reason} ->
        Logger.info(%{approov_token_error: reason})
        {:error, reason}
    end
  end

  # Verifies the Approov token binding for protected endpoints.
  def verify_token_binding(%Plug.Conn{private: %{approov_token_claims: claims}} = conn) do
    with {:ok, binding_value} <- binding_value_for_request(conn),
         :ok <- verify_binding(claims, binding_value) do
      :ok
    else
      {:error, reason} ->
        Logger.info(%{approov_token_binding_error: reason})
        {:error, reason}
    end
  end

  def verify_token_binding(_conn) do
    {:error, :missing_approov_claims}
  end

  # ----------------------------
  # Binding value selection (what gets hashed)
  # ----------------------------
  def binding_value_for_request(%Plug.Conn{request_path: path} = conn) do
    case ApproovApplication.ProtectedRoutes.binding_headers_for_path(path) do
      [] ->
        {:error, :binding_not_required}

      headers ->
        values = Enum.map(headers, &header_value(conn, &1))

        if Enum.any?(values, &is_nil/1) do
          {:error, :missing_token_binding_headers}
        else
          {:ok, Enum.join(values, "")}
        end
    end
  end

  # ----------------------------
  # Approov token fetch
  # ----------------------------
  defp fetch_token(%Plug.Conn{} = conn) do
    case Plug.Conn.get_req_header(conn, @approov_header) do
      [token | _] ->
        {:ok, String.trim(token)}

      [] ->
        case conn.params do
          %{"approov_token" => token} when is_binary(token) -> {:ok, String.trim(token)}
          _ -> {:error, :missing_approov_token}
        end
    end
  end

  # ----------------------------
  # JWT Approov token validation (signature + expiry)
  # ----------------------------
  defp decode_and_verify(token) when is_binary(token) do
    signer = Joken.Signer.create("HS256", approov_secret!())

    case verify_and_validate(token, signer) do
      {:ok, %{"exp" => exp} = claims} ->
        case ensure_not_expired(exp) do
          :ok -> {:ok, claims}
          {:error, _} = error -> error
        end

      {:ok, _claims} ->
        {:error, :missing_expiration}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp ensure_not_expired(exp) when is_integer(exp) do
    now = Joken.current_time()

    if exp > now do
      :ok
    else
      {:error, :approov_token_expired}
    end
  end

  defp ensure_not_expired(exp) when is_float(exp) do
    ensure_not_expired(trunc(exp))
  end

  defp ensure_not_expired(_exp) do
    {:error, :invalid_expiration}
  end

  defp approov_secret! do
    Application.fetch_env!(:approov_quickstart, :approov_secret)
  end

  # ----------------------------
  # Token binding (pay + hash)
  # ----------------------------
  defp verify_binding(%{"pay" => pay} = _claims, binding_value) when is_binary(pay) do
    expected = String.trim(pay)
    computed = hash_binding_value(binding_value)

    if Plug.Crypto.secure_compare(expected, computed) do
      :ok
    else
      {:error, :approov_invalid_token_binding}
    end
  end

  defp verify_binding(_claims, _binding_value) do
    {:error, :approov_token_missing_pay_claim}
  end

  defp hash_binding_value(value) when is_binary(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode64()
  end

  defp header_value(conn, header_name) when is_binary(header_name) do
    case Plug.Conn.get_req_header(conn, header_name) do
      [value | _] ->
        value
        |> String.trim()
        |> empty_to_nil()

      [] ->
        nil
    end
  end

  defp empty_to_nil(""), do: nil
  defp empty_to_nil(value), do: value
end

defmodule ApproovApplication.Plugs.ApproovTokenPlug do
  @moduledoc false

  def init(opts), do: opts

  if Mix.env() in [:dev, :test] do
    def call(%{method: "GET", request_path: "/graphiql"} = conn, _opts), do: conn

    def call(%{method: "POST", request_path: "/graphiql", params: %{"query" => "\n  query IntrospectionQuery" <> _}} = conn, _opts) do
      conn
    end
  end

  def call(conn, _opts) do
    if ApproovApplication.State.approov_enabled?() do
      case ApproovApplication.ApproovToken.verify_token(conn) do
        {:ok, claims} ->
          Plug.Conn.put_private(conn, :approov_token_claims, claims)

        {:error, _reason} ->
          halt_unauthorized(conn)
      end
    else
      conn
    end
  end

  defp halt_unauthorized(conn) do
    conn
    |> Plug.Conn.put_status(401)
    |> Phoenix.Controller.json(%{})
    |> Plug.Conn.halt()
  end
end

defmodule ApproovApplication.Plugs.ApproovTokenBindingPlug do
  @moduledoc false

  def init(opts), do: opts

  if Mix.env() in [:dev, :test] do
    def call(%{method: "GET", request_path: "/graphiql"} = conn, _opts), do: conn

    def call(%{method: "POST", request_path: "/graphiql", params: %{"query" => "\n  query IntrospectionQuery" <> _}} = conn, _opts) do
      conn
    end
  end

  def call(conn, _opts) do
    if ApproovApplication.State.token_binding_enabled?() do
      case ApproovApplication.ApproovToken.verify_token_binding(conn) do
        :ok -> conn
        {:error, _reason} -> halt_unauthorized(conn)
      end
    else
      conn
    end
  end

  defp halt_unauthorized(conn) do
    conn
    |> Plug.Conn.put_status(401)
    |> Phoenix.Controller.json(%{})
    |> Plug.Conn.halt()
  end
end

defmodule ApproovApplication.Plugs.AbsintheContextPlug do
  @moduledoc false

  def init(opts), do: opts

  def call(conn, _opts) do
    context = %{approov_claims: conn.private[:approov_token_claims]}
    Absinthe.Plug.put_options(conn, context: context)
  end
end

defmodule ApproovApplication.ApproovController do
  use Phoenix.Controller, namespace: ApproovApplication

  def home(conn, _params) do
    json(conn, ApproovApplication.State.info_payload("Approov demo API is running on port 8080."))
  end

  def approov_state(conn, _params) do
    json(conn, ApproovApplication.State.state_payload())
  end

  def enable_approov(conn, _params) do
    ApproovApplication.State.enable_approov()
    json(conn, ApproovApplication.State.state_payload())
  end

  def disable_approov(conn, _params) do
    ApproovApplication.State.disable_approov()
    json(conn, ApproovApplication.State.state_payload())
  end

  def enable_token_binding(conn, _params) do
    ApproovApplication.State.enable_binding()
    json(conn, ApproovApplication.State.state_payload())
  end

  def disable_token_binding(conn, _params) do
    ApproovApplication.State.disable_binding()
    json(conn, ApproovApplication.State.state_payload())
  end

  def unprotected(conn, _params) do
    json(conn, ApproovApplication.State.info_payload("Unprotected endpoint '/unprotected'; no Approov checks performed."))
  end

  def token_check(conn, _params) do
    json(conn, ApproovApplication.State.info_payload("Protected endpoint '/token-check'; Approov token verified."))
  end

  def token_binding(conn, _params) do
    response = ApproovApplication.State.info_payload(
      "Protected endpoint '/token-binding'; Approov token binding enforced."
    )

    response =
      response
      |> Map.put(:authorizationHeaderPresent, header_present?(conn, "authorization"))

    json(conn, response)
  end

  def token_double_binding(conn, _params) do
    response = ApproovApplication.State.info_payload(
      "Protected endpoint '/token-double-binding'; dual token binding enforced."
    )

    response =
      response
      |> Map.put(:authorizationHeaderPresent, header_present?(conn, "authorization"))
      |> Map.put(:contentDigestHeaderPresent, header_present?(conn, "content-digest"))

    json(conn, response)
  end

  defp header_present?(conn, header) do
    case Plug.Conn.get_req_header(conn, header) do
      [value | _] -> String.trim(value) != ""
      [] -> false
    end
  end
end

defmodule ApproovApplication.Schema do
  use Absinthe.Schema

  query do
    field :approov_state, :approov_state do
      resolve &ApproovApplication.Resolvers.StatusResolver.status/3
    end
  end

  object :approov_state do
    field :approov_enabled, :boolean
    field :token_binding_enabled, :boolean
    field :details, :string
  end
end

defmodule ApproovApplication.Resolvers.StatusResolver do
  def status(_parent, _args, _resolution) do
    {:ok, ApproovApplication.State.info_payload("Approov state via GraphQL.")}
  end
end

defmodule ApproovApplication.Router do
  use Phoenix.Router

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :approov_token do
    plug ApproovApplication.Plugs.ApproovTokenPlug
  end

  pipeline :approov_token_binding do
    plug ApproovApplication.Plugs.ApproovTokenBindingPlug
  end

  pipeline :graphql do
    plug ApproovApplication.Plugs.AbsintheContextPlug
  end

  scope "/" do
    pipe_through :api

    get "/", ApproovApplication.ApproovController, :home
    get "/approov-state", ApproovApplication.ApproovController, :approov_state
    post "/approov/enable", ApproovApplication.ApproovController, :enable_approov
    post "/approov/disable", ApproovApplication.ApproovController, :disable_approov
    post "/token-binding/enable", ApproovApplication.ApproovController, :enable_token_binding
    post "/token-binding/disable", ApproovApplication.ApproovController, :disable_token_binding
    get "/unprotected", ApproovApplication.ApproovController, :unprotected
  end

  scope "/" do
    pipe_through [:api, :approov_token]

    get "/token-check", ApproovApplication.ApproovController, :token_check
  end

  scope "/" do
    pipe_through [:api, :approov_token, :approov_token_binding]

    get "/token-binding", ApproovApplication.ApproovController, :token_binding
    get "/token-double-binding", ApproovApplication.ApproovController, :token_double_binding
  end

  scope "/graphql" do
    pipe_through [:api, :approov_token, :graphql]

    forward "/", Absinthe.Plug, schema: ApproovApplication.Schema
  end

  if Mix.env() in [:dev, :test] do
    scope "/graphiql" do
      pipe_through [:api, :graphql]

      forward "/", Absinthe.Plug.GraphiQL,
        schema: ApproovApplication.Schema,
        interface: :simple
    end
  end
end

defmodule ApproovApplication.Endpoint do
  use Phoenix.Endpoint, otp_app: :approov_quickstart

  plug Plug.RequestId
  plug Plug.Logger
  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Jason
  plug Plug.MethodOverride
  plug Plug.Head

  plug ApproovApplication.Router
end
