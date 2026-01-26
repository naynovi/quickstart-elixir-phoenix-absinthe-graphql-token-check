defmodule ApproovQuickstart.MixProject do
  use Mix.Project

  def project do
    [
      app: :approov_quickstart,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {ApproovApplication.Application, []},
      extra_applications: [:logger, :runtime_tools, :crypto]
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.8.3"},
      {:plug_cowboy, "~> 2.7.5"},
      {:jason, "~> 1.4.4"},
      {:absinthe_plug, "~> 1.5.9"},
      {:joken, "~> 2.6.2"}
    ]
  end
end
