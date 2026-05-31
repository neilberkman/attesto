defmodule Attesto.JWKSTest do
  @moduledoc false
  # from_config/1 resolves the keystore from the global :attesto app env
  # (via Factory.config), so these run serially.
  use ExUnit.Case, async: false

  alias Attesto.JWKS
  alias Attesto.Key
  alias Attesto.Test.Factory

  describe "from_pems/1" do
    test "emits one public JWK per key with kid/use/alg and no private members" do
      pem = Factory.rsa_pem()

      assert %{"keys" => [jwk]} = JWKS.from_pems([pem])

      assert jwk["kty"] == "RSA"
      assert jwk["kid"] == Key.kid(pem)
      assert jwk["use"] == "sig"
      assert jwk["alg"] == "RS256"
      assert is_binary(jwk["n"])
      assert is_binary(jwk["e"])

      for private_member <- ~w(d p q dp dq qi) do
        refute Map.has_key?(jwk, private_member), "JWK must not leak #{private_member}"
      end
    end

    test "publishes every key in a rotation set, keyed distinctly" do
      pem1 = Factory.rsa_pem()
      pem2 = Factory.rsa_pem()

      assert %{"keys" => keys} = JWKS.from_pems([pem1, pem2])
      assert length(keys) == 2
      assert MapSet.new(keys, & &1["kid"]) == MapSet.new([Key.kid(pem1), Key.kid(pem2)])
    end

    test "de-duplicates a key listed more than once" do
      pem = Factory.rsa_pem()
      assert %{"keys" => [_one]} = JWKS.from_pems([pem, pem])
    end

    test "an empty key list yields an empty set" do
      assert %{"keys" => []} = JWKS.from_pems([])
    end

    test "an EC P-256 key is published as ES256, not mislabelled as RS256" do
      ec_pem =
        {:ec, "P-256"}
        |> JOSE.JWK.generate_key()
        |> JOSE.JWK.to_pem()
        |> elem(1)

      assert %{"keys" => [jwk]} = JWKS.from_pems([ec_pem])
      assert jwk["kty"] == "EC"
      assert jwk["crv"] == "P-256"
      assert jwk["alg"] == "ES256"
      assert jwk["kid"] == Key.kid(ec_pem)
      refute Map.has_key?(jwk, "d")
    end
  end

  describe "from_config/1" do
    test "builds the set from the config's keystore verification keys" do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)

      assert %{"keys" => [jwk]} = JWKS.from_config(config)
      assert jwk["kid"] == Key.kid(pem)
      assert jwk["use"] == "sig"
    end
  end
end
