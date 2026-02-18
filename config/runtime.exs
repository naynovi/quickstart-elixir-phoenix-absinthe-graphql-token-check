import Config

approov_secret_env = "APPROOV_BASE64URL_SECRET"
approov_secret_placeholder = "approov_base64url_secret_here"

approov_secret_base64url = System.get_env(approov_secret_env)

if is_nil(approov_secret_base64url) or String.trim(approov_secret_base64url) == "" or
     approov_secret_base64url == approov_secret_placeholder do
  raise "#{approov_secret_env} is not set. Invalid examples: APPROOV_BASE64URL_SECRET=approov_base64url_secret_here or APPROOV_BASE64URL_SECRET="
end

approov_secret =
  case Base.url_decode64(approov_secret_base64url, padding: false) do
    {:ok, secret} when byte_size(secret) > 0 ->
      secret

    {:ok, _empty_secret} ->
      raise "#{approov_secret_env} is invalid: decoded value is empty"

    :error ->
      raise "#{approov_secret_env} must be base64url encoded"
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
