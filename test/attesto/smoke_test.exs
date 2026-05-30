defmodule Attesto.SmokeTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.Test.Factory

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  describe "client token round trip" do
    test "mint then verify", %{config: config} do
      assert {:ok, token} =
               Attesto.Token.mint(config, %{
                 kind: "client",
                 sub: "oc_live_abc",
                 scopes: ["documents.read", "documents.write"],
                 claims: %{"client_id" => "oc_live_abc"}
               })

      assert token.token_type == "Bearer"
      assert token.expires_in == 900
      assert token.scope == "documents.read documents.write"

      assert {:ok, claims} = Attesto.Token.verify(config, token.access_token)
      assert claims["sub"] == "oc_live_abc"
      assert claims["client_id"] == "oc_live_abc"
      assert claims["principal_kind"] == "client"
      assert claims["typ"] == "access"
    end

    test "sub not matching the kind prefix is rejected at mint", %{config: config} do
      assert {:error, :invalid_sub} =
               Attesto.Token.mint(config, %{
                 kind: "client",
                 sub: "usr_wrong",
                 scopes: [],
                 claims: %{"client_id" => "x"}
               })
    end

    test "missing required client_id is rejected at mint", %{config: config} do
      assert {:error, :invalid_claims} =
               Attesto.Token.mint(config, %{kind: "client", sub: "oc_x", scopes: []})
    end
  end

  describe "user token round trip" do
    test "mint then verify with session claims", %{config: config} do
      assert {:ok, token} =
               Attesto.Token.mint(config, %{
                 kind: "user",
                 sub: "usr_42",
                 scopes: ["documents.read"],
                 claims: %{"act" => "ac_7", "sid" => "sess_1", "token_version" => 3}
               })

      assert {:ok, claims} = Attesto.Token.verify(config, token.access_token)
      assert claims["sub"] == "usr_42"
      assert claims["act"] == "ac_7"
      assert claims["token_version"] == 3
      assert claims["principal_kind"] == "user"
    end
  end

  describe "verify failure modes" do
    test "wrong issuer config rejects the token", %{pem: pem, config: config} do
      {:ok, token} =
        Attesto.Token.mint(config, %{kind: "client", sub: "oc_x", scopes: [], claims: %{"client_id" => "x"}})

      other = Factory.config(pem, issuer: "https://evil.example/")
      assert {:error, :invalid_issuer} = Attesto.Token.verify(other, token.access_token)
    end

    test "expired token", %{config: config} do
      past = System.system_time(:second) - 10_000

      {:ok, token} =
        Attesto.Token.mint(
          config,
          %{kind: "client", sub: "oc_x", scopes: [], claims: %{"client_id" => "x"}},
          now: past
        )

      assert {:error, :expired} = Attesto.Token.verify(config, token.access_token)
    end

    test "garbage is invalid_token", %{config: config} do
      assert {:error, :invalid_token} = Attesto.Token.verify(config, "not.a.jwt")
    end

    test "a token signed by a different key fails signature", %{config: config} do
      foreign = Factory.foreign_config(Factory.rsa_pem())

      {:ok, token} =
        Attesto.Token.mint(foreign, %{kind: "client", sub: "oc_x", scopes: [], claims: %{"client_id" => "x"}})

      assert {:error, :invalid_signature} = Attesto.Token.verify(config, token.access_token)
    end
  end

  describe "DPoP binding end to end" do
    test "mint DPoP-bound, verify proof, verify token with jkt", %{config: config} do
      {proof, jkt} = Factory.dpop_proof(htu: "https://api.example.com/oauth/token")

      assert {:ok, %{jkt: ^jkt}} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "POST",
                 http_uri: "https://api.example.com/oauth/token"
               )

      {:ok, token} =
        Attesto.Token.mint(
          config,
          %{kind: "client", sub: "oc_x", scopes: ["documents.read"], claims: %{"client_id" => "x"}},
          dpop_jkt: jkt
        )

      assert token.token_type == "DPoP"
      assert {:ok, _claims} = Attesto.Token.verify(config, token.access_token, dpop_jkt: jkt)
      assert {:error, :dpop_proof_required} = Attesto.Token.verify(config, token.access_token)

      assert {:error, :dpop_binding_mismatch} =
               Attesto.Token.verify(config, token.access_token, dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    end

    test "alg=none proof is rejected", %{config: _config} do
      # A hand-built unsecured JWS: header.payload. (empty sig)
      header = Base.url_encode64(JSON.encode!(%{"typ" => "dpop+jwt", "alg" => "none"}), padding: false)

      payload =
        Base.url_encode64(JSON.encode!(%{"htm" => "POST", "htu" => "https://api.example.com/x"}), padding: false)

      proof = header <> "." <> payload <> "."

      assert {:error, :invalid_alg} =
               Attesto.DPoP.verify_proof(proof, http_method: "POST", http_uri: "https://api.example.com/x")
    end
  end

  describe "scope matching" do
    test "wildcard grants concrete" do
      catalog = Attesto.Scope.new_catalog(~w(documents.read documents.write reports.read))
      assert Attesto.Scope.grants?(catalog, ["documents.*"], "documents.write")
      refute Attesto.Scope.grants?(catalog, ["documents.read"], "documents.write")
      refute Attesto.Scope.grants?(catalog, ["documents.*"], "reports.read")
    end
  end

  describe "thumbprint shape" do
    test "canonical 43-char passes, garbage fails" do
      good = Attesto.Thumbprint.of("hello")
      assert Attesto.Thumbprint.valid?(good)
      refute Attesto.Thumbprint.valid?("short")
      refute Attesto.Thumbprint.valid?(String.duplicate("A", 43) <> "B")
    end
  end
end
