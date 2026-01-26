import Config

config :logger, level: :debug

config :approov_quickstart, ApproovApplication.Endpoint,
  code_reloader: false,
  debug_errors: true
