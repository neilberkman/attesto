defmodule Attesto.Test.PS256Keystore do
  @moduledoc false

  @behaviour Attesto.Keystore

  alias Attesto.Test.Factory

  @key {__MODULE__, :pem}

  @impl Attesto.Keystore
  def signing_pem do
    case :persistent_term.get(@key, nil) do
      nil ->
        pem = Factory.rsa_pem()
        :persistent_term.put(@key, pem)
        pem

      pem ->
        pem
    end
  end

  @impl Attesto.Keystore
  def verification_pems, do: [signing_pem()]

  @impl Attesto.Keystore
  def signing_alg, do: "PS256"

  @impl Attesto.Keystore
  def key_algs, do: %{Attesto.Key.kid(signing_pem()) => "PS256"}
end
