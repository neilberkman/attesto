defmodule Attesto.KeystoreKeyTest do
  @moduledoc false
  # async: false - the Keystore.Static cases mutate the shared :attesto
  # application environment.
  use ExUnit.Case, async: false

  alias Attesto.Key
  alias Attesto.Keystore.Static
  alias Attesto.Test.Factory
  alias Attesto.Thumbprint

  describe "Key.public_pem/1" do
    test "derives a stable SPKI public PEM from a private PEM" do
      private_pem = Factory.rsa_pem()

      public_pem = Key.public_pem(private_pem)

      assert public_pem =~ "-----BEGIN PUBLIC KEY-----"
      assert public_pem =~ "-----END PUBLIC KEY-----"
      # SPKI, not the PKCS#1 RSA private/public markers.
      refute public_pem =~ "RSA PRIVATE KEY"
      refute public_pem =~ "RSA PUBLIC KEY"
    end

    test "deriving the public key twice yields an identical PEM" do
      private_pem = Factory.rsa_pem()

      assert Key.public_pem(private_pem) == Key.public_pem(private_pem)
    end

    test "the derived public key signs-then-verifies against the private key" do
      private_pem = Factory.rsa_pem()

      private_jwk = JOSE.JWK.from_pem(private_pem)
      public_jwk = JOSE.JWK.from_pem(Key.public_pem(private_pem))

      signed = JOSE.JWT.sign(private_jwk, %{"alg" => "RS256"}, %{"hello" => "world"})
      {_, compact} = JOSE.JWS.compact(signed)

      assert {true, _jwt, _jws} = JOSE.JWT.verify_strict(public_jwk, ["RS256"], compact)
    end

    test "raises ArgumentError on a PEM with no key entry" do
      assert_raise ArgumentError, ~r/no key entry/, fn ->
        Key.public_pem("not a pem at all")
      end
    end
  end

  describe "Key.kid/1" do
    test "is stable for a given key" do
      private_pem = Factory.rsa_pem()

      assert Key.kid(private_pem) == Key.kid(private_pem)
    end

    test "differs for a different key" do
      pem_a = Factory.rsa_pem()
      pem_b = Factory.rsa_pem()

      refute Key.kid(pem_a) == Key.kid(pem_b)
    end

    test "is the same for the private PEM and its derived public PEM (thumbprint is over public members)" do
      private_pem = Factory.rsa_pem()
      public_pem = Key.public_pem(private_pem)

      assert Key.kid(private_pem) == Key.kid(public_pem)
    end

    test "is a canonical RFC 7638 SHA-256 thumbprint shape" do
      kid = Factory.rsa_pem() |> Key.kid()

      assert Thumbprint.valid?(kid)
    end
  end

  describe "Keystore.Static.signing_pem/0" do
    test "returns the PEM configured under the :attesto app env" do
      pem = Factory.rsa_pem()
      Application.put_env(:attesto, Static, signing_pem: pem)
      on_exit(fn -> Application.delete_env(:attesto, Static) end)

      assert Static.signing_pem() == pem
    end

    test "raises a helpful ArgumentError when :signing_pem is unset" do
      Application.delete_env(:attesto, Static)

      error =
        assert_raise ArgumentError, fn ->
          Static.signing_pem()
        end

      assert error.message =~ "no :signing_pem configured"
      assert error.message =~ "config :attesto"
    end

    test "raises when :signing_pem is the empty string" do
      Application.put_env(:attesto, Static, signing_pem: "")
      on_exit(fn -> Application.delete_env(:attesto, Static) end)

      assert_raise ArgumentError, ~r/:signing_pem is set but empty/, fn ->
        Static.signing_pem()
      end
    end
  end

  describe "Keystore.Static.verification_pems/0" do
    test "defaults to [signing_pem] when :verification_pems is omitted" do
      pem = Factory.rsa_pem()
      Application.put_env(:attesto, Static, signing_pem: pem)
      on_exit(fn -> Application.delete_env(:attesto, Static) end)

      assert Static.verification_pems() == [pem]
    end

    test "honors an explicit :verification_pems list" do
      current_pem = Factory.rsa_pem()
      previous_pem = Factory.rsa_pem()

      Application.put_env(:attesto, Static,
        signing_pem: current_pem,
        verification_pems: [current_pem, previous_pem]
      )

      on_exit(fn -> Application.delete_env(:attesto, Static) end)

      assert Static.verification_pems() == [current_pem, previous_pem]
    end

    test "falls back to [signing_pem] when :verification_pems is an empty list" do
      pem = Factory.rsa_pem()
      Application.put_env(:attesto, Static, signing_pem: pem, verification_pems: [])
      on_exit(fn -> Application.delete_env(:attesto, Static) end)

      assert Static.verification_pems() == [pem]
    end

    test "raises on a non-list :verification_pems (a typo must not silently default)" do
      pem = Factory.rsa_pem()
      # The classic typo: a bare string instead of a list. Previously this
      # silently collapsed to [signing_pem], hiding a rotation misconfig.
      Application.put_env(:attesto, Static, signing_pem: pem, verification_pems: "")
      on_exit(fn -> Application.delete_env(:attesto, Static) end)

      assert_raise ArgumentError, ~r/:verification_pems must be a list/, fn ->
        Static.verification_pems()
      end
    end

    test "raises when a :verification_pems entry is not a non-empty PEM string" do
      pem = Factory.rsa_pem()
      Application.put_env(:attesto, Static, signing_pem: pem, verification_pems: [pem, ""])
      on_exit(fn -> Application.delete_env(:attesto, Static) end)

      assert_raise ArgumentError, ~r/entries must each be a non-empty/, fn ->
        Static.verification_pems()
      end
    end
  end
end
