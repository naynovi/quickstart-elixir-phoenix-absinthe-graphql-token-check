defmodule ApproovApplication.Application do
  use Application

  def start(_type, _args) do
    ApproovApplication.ApproovToken.log_secret_status()

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
      %{approov: :required, binding_headers: ["authorization", "sessionid"]}
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
  @secret_env "APPROOV_BASE64URL_SECRET"
  @secret_placeholder "approov_base64url_secret_here"
  @secret_log_missing_key {:approov_secret_log, :missing}
  @secret_log_invalid_key {:approov_secret_log, :invalid}

  def log_secret_status do
    _ = approov_secret()
    :ok
  end

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
        Logger.debug(%{approov_token_error: reason})
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
        Logger.debug(%{approov_token_binding_error: reason})
        {:error, reason}
    end
  end

  def verify_token_binding(_conn) do
    {:error, :missing_approov_claims}
  end

  # Binding value selection (what gets hashed)
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

  # Approov token fetch
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

  # JWT Approov token validation (signature + expiry)
  defp decode_and_verify(token) when is_binary(token) do
    with {:ok, secret} <- approov_secret(),
         signer <- Joken.Signer.create("HS256", secret),
         {:ok, %{"exp" => exp} = claims} <- verify_and_validate(token, signer),
         :ok <- ensure_not_expired(exp) do
      {:ok, claims}
    else
      {:ok, _claims} -> {:error, :missing_expiration}
      {:error, reason} -> {:error, reason}
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

  defp approov_secret do
    case System.get_env(@secret_env) do
      nil ->
        case Application.fetch_env(:approov_quickstart, :approov_secret) do
          {:ok, secret} ->
            {:ok, secret}

          :error ->
            log_secret_issue_once(
              @secret_log_missing_key,
              "Required secret is not set. Invalid examples: APPROOV_BASE64URL_SECRET=approov_base64url_secret_here or APPROOV_BASE64URL_SECRET="
            )
            {:error, :approov_secret_missing}
        end

      value ->
        trimmed_value = String.trim(value)

        cond do
          trimmed_value == "" or value == @secret_placeholder ->
            log_secret_issue_once(
              @secret_log_missing_key,
              "Required secret is not set. Invalid examples: APPROOV_BASE64URL_SECRET=approov_base64url_secret_here or APPROOV_BASE64URL_SECRET="
            )
            {:error, :approov_secret_missing}

          true ->
            case Base.url_decode64(value, padding: false) do
              {:ok, secret} when byte_size(secret) > 0 ->
                {:ok, secret}

              {:ok, _empty_secret} ->
                log_secret_issue_once(@secret_log_invalid_key, "Required secret is invalid: decoded value is empty")
                {:error, :approov_secret_invalid}

              :error ->
                log_secret_issue_once(@secret_log_invalid_key, "Required secret is invalid")
                {:error, :approov_secret_invalid}
            end
        end
    end
  end

  defp log_secret_issue_once(key, message) do
    case :persistent_term.get(key, false) do
      true ->
        :ok

      false ->
        Logger.error(message, secret_env: @secret_env)
        :persistent_term.put(key, true)
    end
  end

  # Token binding (pay + hash)
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

defmodule ApproovApplication.Plugs.RequestLoggingPlug do
  @moduledoc false
  require Logger

  def init(opts), do: opts

  def call(conn, _opts) do
    Plug.Conn.register_before_send(conn, fn conn ->
      status = conn.status || 0

      if status in [200, 401] do
        metadata = request_metadata(conn, status)
        Logger.info("http.request.completed #{format_metadata(metadata)}", metadata)
      end

      conn
    end)
  end

  defp request_metadata(conn, status) do
    [
      summary: summary(conn, status),
      method: conn.method,
      path: conn.request_path,
      status: status,
      ip: remote_ip(conn),
      port: conn.port,
      approovEnabled: ApproovApplication.State.approov_enabled?(),
      tokenBindingEnabled: ApproovApplication.State.token_binding_enabled?(),
      required_headers: required_headers(conn),
      approov_reason: format_reason(conn.private[:approov_failure_reason])
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end

  defp format_metadata(metadata) do
    metadata
    |> Enum.into(%{})
    |> inspect()
  end

  defp summary(conn, 401) do
    "approov_failed:" <> failure_category(conn.private[:approov_failure_reason])
  end

  defp summary(conn, 200) do
    if protected_path?(conn.request_path) do
      if ApproovApplication.State.approov_enabled?() do
        "approov_ok"
      else
        "approov_disabled"
      end
    else
      "ok"
    end
  end

  defp summary(_conn, _status), do: "ok"

  defp failure_category(nil), do: "unauthorized"
  defp failure_category(:missing_approov_token), do: "missing_approov_token"
  defp failure_category(:missing_token_binding_headers), do: "missing_binding_header"
  defp failure_category(:approov_invalid_token_binding), do: "binding_mismatch"
  defp failure_category(:approov_token_missing_pay_claim), do: "binding_mismatch"
  defp failure_category(:approov_secret_missing), do: "missing_approov_secret"
  defp failure_category(:approov_secret_invalid), do: "invalid_approov_secret"
  defp failure_category(:missing_approov_claims), do: "token_verification_failed"
  defp failure_category(:binding_not_required), do: "token_verification_failed"
  defp failure_category(_reason), do: "token_verification_failed"

  defp format_reason(nil), do: nil
  defp format_reason(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp format_reason(reason) when is_binary(reason), do: reason
  defp format_reason(reason), do: inspect(reason)

  defp required_headers(conn) do
    path = conn.request_path

    if ApproovApplication.State.approov_enabled?() and protected_path?(path) do
      headers = ["Approov-Token"]

      if ApproovApplication.State.token_binding_enabled?() do
        binding_headers = ApproovApplication.ProtectedRoutes.binding_headers_for_path(path)
        headers ++ Enum.map(binding_headers, &canonical_header/1)
      else
        headers
      end
    else
      []
    end
  end

  defp protected_path?(path) when is_binary(path) do
    Map.has_key?(ApproovApplication.ProtectedRoutes.levels(), path)
  end

  defp canonical_header("authorization"), do: "Authorization"
  defp canonical_header("sessionid"), do: "SessionId"

  defp canonical_header(header) when is_binary(header) do
    header
    |> String.split("-")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join("-")
  end

  defp remote_ip(%Plug.Conn{remote_ip: nil}), do: nil

  defp remote_ip(%Plug.Conn{remote_ip: ip}) do
    ip
    |> :inet.ntoa()
    |> to_string()
  end
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

        {:error, reason} ->
          ApproovApplication.Plugs.ApproovUnauthorized.reject(conn, reason)
      end
    else
      conn
    end
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
        {:error, reason} -> ApproovApplication.Plugs.ApproovUnauthorized.reject(conn, reason)
      end
    else
      conn
    end
  end
end

defmodule ApproovApplication.Plugs.ApproovUnauthorized do
  @moduledoc false

  # Keep auth failure handling centralized. Upstream verification returns
  # domain errors; this plug only maps them to an HTTP 401 boundary response.
  def reject(conn, reason) do
    conn
    |> Plug.Conn.put_private(:approov_failure_reason, reason)
    |> Plug.Conn.resp(401, "")
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
  use Phoenix.Controller, formats: [:json]

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
      |> Map.put(:sessionIdHeaderPresent, header_present?(conn, "sessionid"))

    json(conn, response)
  end

  defp header_present?(conn, header) do
    case Plug.Conn.get_req_header(conn, header) do
      [value | _] -> String.trim(value) != ""
      [] -> false
    end
  end
end

defmodule ApproovApplication.SchemaPrototype do
  @moduledoc false

  use Absinthe.Schema.Prototype

  # Some Absinthe toolchains may request the GraphQL @oneOf directive while
  # inlining prototype directive functions. Define it explicitly to avoid
  # function-clause crashes in schema compilation.
  directive :one_of do
    description "Indicates an input object expects exactly one supplied field."
    repeatable false
    on [:input_object]
    expand &__MODULE__.expand_one_of/2
  end

  def expand_one_of(_args, node), do: node
end

defmodule ApproovApplication.Schema do
  use Absinthe.Schema
  @prototype_schema ApproovApplication.SchemaPrototype

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
  # Keep startup info logs, but silence request logs at info level.
  plug Plug.Logger, log: :debug
  plug ApproovApplication.Plugs.RequestLoggingPlug
  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Jason
  plug Plug.MethodOverride
  plug Plug.Head

  plug ApproovApplication.Router
end
