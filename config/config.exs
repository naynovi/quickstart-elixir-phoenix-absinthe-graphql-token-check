import Config

config :phoenix, :json_library, Jason

config :approov_quickstart, ApproovApplication.Endpoint,
  url: [host: "localhost", port: 8080],
  http: [ip: {0, 0, 0, 0}, port: 8080],
  secret_key_base: "change_me_in_env",
  render_errors: [accepts: ~w(json)],
  server: true,
  check_origin: false

config :logger, level: :info
