defmodule Attesto.Test.RotationKeystore do
  @moduledoc false
  # A keystore whose verification set holds MORE THAN ONE key, so a test
  # can model a rotation window (two trusted PEMs) without touching the
  # shared Factory. Signing material and the verification list are read
  # from the :attesto app env under this module's own key, kept separate
  # from Attesto.Keystore.Static so the two never collide in one VM.
  #
  # Configure with `install/2`, which also registers an on_exit cleanup:
  #
  #     {signing, verification} = {pem_a, [pem_a, pem_b]}
  #     Attesto.Test.RotationKeystore.install(signing, verification)
  #     config = Attesto.Test.RotationKeystore.config()

  @behaviour Attesto.Keystore

  @issuer "https://api.example.com/"
  @audience "https://api.example.com/"

  @impl true
  def signing_pem do
    :attesto
    |> Application.get_env(__MODULE__, [])
    |> Keyword.fetch!(:signing_pem)
  end

  @impl true
  def verification_pems do
    :attesto
    |> Application.get_env(__MODULE__, [])
    |> Keyword.fetch!(:verification_pems)
  end

  @doc """
  Set the signing PEM and the (possibly multi-element) verification PEM
  list under the :attesto app env, registering teardown on the calling
  test. Mutates global app env, so callers MUST be `async: false`.
  """
  def install(signing_pem, verification_pems) when is_binary(signing_pem) and is_list(verification_pems) do
    Application.put_env(:attesto, __MODULE__,
      signing_pem: signing_pem,
      verification_pems: verification_pems
    )

    ExUnit.Callbacks.on_exit(fn -> Application.delete_env(:attesto, __MODULE__) end)
    :ok
  end

  @doc """
  A `Config` wired to this keystore with a single `client` principal kind.
  Same issuer/audience as `Attesto.Test.Factory` so hand-built claim sets
  are interchangeable.
  """
  def config(overrides \\ []) do
    [
      issuer: @issuer,
      audience: @audience,
      keystore: __MODULE__,
      principal_kinds: [
        Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
      ]
    ]
    |> Keyword.merge(overrides)
    |> Attesto.Config.new()
  end
end
