import Config

approov_secret_base64url =
  System.get_env("APPROOV_BASE64URL_SECRET") ||
    raise "APPROOV_BASE64URL_SECRET is required"

approov_secret =
  case Base.url_decode64(approov_secret_base64url, padding: false) do
    {:ok, secret} ->
      secret

    :error ->
      raise "APPROOV_BASE64URL_SECRET must be base64url encoded"
  end

http_port = System.get_env("HTTP_PORT") || "8080"
port = String.to_integer(http_port)

host = System.get_env("SERVER_HOSTNAME") || "0.0.0.0"

secret_key_base = System.get_env("SECRET_KEY_BASE") || "change_me_in_env"

config :approov_quickstart,
  approov_secret: approov_secret

config :approov_quickstart, ApproovApplication.Endpoint,
  http: [ip: {0, 0, 0, 0}, port: port],
  url: [host: host, port: port],
  secret_key_base: secret_key_base,
  server: true
