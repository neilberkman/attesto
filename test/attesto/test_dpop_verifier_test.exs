defmodule Attesto.Test.DPoPVerifierTest do
  # Not async: the token-verification cases read the signing key from the
  # global `Attesto.Keystore.Static` application env that `Factory.config/2`
  # installs and tears down per test. Running concurrently with other modules
  # that mutate that singleton env races (a sibling's on_exit can delete the
  # PEM mid-test), so this module runs serially.
  use ExUnit.Case, async: false

  alias Attesto.Test.DPoP, as: Fixture
  alias Attesto.Test.DPoPVerifier, as: Verifier
  alias Attesto.Test.Factory

  @url "https://api.example.test/resource"

  setup do
    config = Factory.config(Factory.rsa_pem())
    jwk = Fixture.generate_key()
    principal = %{kind: "client", sub: "oc_acme", scopes: ["read"], claims: %{"client_id" => "acme"}}

    {:ok, config: config, jwk: jwk, principal: principal}
  end

  describe "valid DPoP request" do
    test "verifies a proof + bound token end to end", ctx do
      {token, _resp} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)
      proof = Fixture.proof(ctx.jwk, "GET", @url, access_token: token)

      assert {:ok, verified} =
               Verifier.verify_request(
                 config: ctx.config,
                 method: "GET",
                 url: @url,
                 headers: [
                   {"authorization", "DPoP " <> token},
                   {"dpop", proof}
                 ],
                 verify_token: true
               )

      assert verified.scheme == :dpop
      assert verified.jkt == Attesto.DPoP.compute_jkt(JOSE.JWK.to_public(ctx.jwk))
      assert verified.claims["sub"] == "oc_acme"
      assert verified.proof.htm == "GET"
    end

    test "the access_token defaults to the one in the Authorization header", ctx do
      {token, _resp} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)
      proof = Fixture.proof(ctx.jwk, "GET", @url, access_token: token)

      assert {:ok, %{claims: %{"sub" => "oc_acme"}}} =
               Verifier.verify_request(
                 config: ctx.config,
                 method: "GET",
                 url: @url,
                 headers: [{"authorization", "DPoP " <> token}, {"dpop", proof}],
                 verify_token: true
               )
    end
  end

  describe "proof-only request" do
    test "verifies when no access token is required (no token verification)", ctx do
      proof = Fixture.proof(ctx.jwk, "POST", @url)

      assert {:ok, verified} =
               Verifier.verify_request(
                 method: "POST",
                 url: @url,
                 headers: [{"dpop", proof}]
               )

      assert verified.scheme == :dpop
      assert verified.jkt == Attesto.DPoP.compute_jkt(JOSE.JWK.to_public(ctx.jwk))
      assert verified.claims == nil
    end
  end

  describe "invalid proof" do
    test "wrong htm returns an invalid_dpop_proof DPoP challenge", ctx do
      proof = Fixture.invalid_proof(ctx.jwk, :wrong_htm, "GET", @url)

      assert {:error, challenge} =
               Verifier.verify_request(method: "GET", url: @url, headers: [{"dpop", proof}])

      assert challenge.status == 401
      assert challenge.scheme == :dpop
      assert challenge.error == "invalid_dpop_proof"
      assert challenge.error_reason == :invalid_htm
      assert "DPoP error=\"invalid_dpop_proof\"" <> _ = challenge.www_authenticate
      assert {"www-authenticate", challenge.www_authenticate} in challenge.headers
    end

    test "wrong htu returns an invalid_dpop_proof DPoP challenge", ctx do
      proof = Fixture.invalid_proof(ctx.jwk, :wrong_htu, "GET", @url)

      assert {:error, %{error: "invalid_dpop_proof", error_reason: :invalid_htu, scheme: :dpop}} =
               Verifier.verify_request(method: "GET", url: @url, headers: [{"dpop", proof}])
    end
  end

  describe "nonce" do
    test "a missing nonce with a demanding nonce_check returns use_dpop_nonce + a DPoP-Nonce header", ctx do
      proof = Fixture.proof(ctx.jwk, "GET", @url)

      nonce_check = fn
        nil -> {:error, :use_dpop_nonce}
        _present -> :ok
      end

      assert {:error, challenge} =
               Verifier.verify_request(
                 method: "GET",
                 url: @url,
                 headers: [{"dpop", proof}],
                 nonce_check: nonce_check,
                 nonce_issue: fn -> "fresh-nonce" end
               )

      assert challenge.error == "use_dpop_nonce"
      assert challenge.error_reason == :use_dpop_nonce
      assert challenge.scheme == :dpop
      assert challenge.dpop_nonce == "fresh-nonce"
      assert {"dpop-nonce", "fresh-nonce"} in challenge.headers
    end
  end

  describe "DPoP-bound token presented as Bearer" do
    test "fails with a DPoP challenge (dpop_proof_required)", ctx do
      {token, _resp} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)

      assert {:error, challenge} =
               Verifier.verify_request(
                 config: ctx.config,
                 method: "GET",
                 url: @url,
                 headers: [{"authorization", "Bearer " <> token}],
                 verify_token: true
               )

      assert challenge.status == 401
      assert challenge.scheme == :dpop
      assert challenge.error == "invalid_token"
      assert challenge.error_reason == :dpop_proof_required
    end

    test "a DPoP header alongside Bearer is rejected as scheme mixing", ctx do
      {token, _resp} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)
      proof = Fixture.proof(ctx.jwk, "GET", @url, access_token: token)

      assert {:error, %{scheme: :dpop, error_reason: :dpop_scheme_required}} =
               Verifier.verify_request(
                 config: ctx.config,
                 method: "GET",
                 url: @url,
                 headers: [{"authorization", "Bearer " <> token}, {"dpop", proof}],
                 verify_token: true
               )
    end
  end

  describe "full mint + proof + verify path" do
    test "Attesto.Test.DPoP fixtures verify through the harness with replay protection", ctx do
      {token, _resp} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)
      proof = Fixture.proof(ctx.jwk, "GET", @url, access_token: token)

      seen = :ets.new(:replay, [:set, :private])
      replay_check = fn jti, _ttl -> if :ets.insert_new(seen, {jti, true}), do: :ok, else: {:error, :replay} end

      request = [
        config: ctx.config,
        method: "GET",
        url: @url,
        headers: [{"authorization", "DPoP " <> token}, {"dpop", proof}],
        verify_token: true,
        replay_check: replay_check
      ]

      assert {:ok, %{claims: %{"sub" => "oc_acme"}}} = Verifier.verify_request(request)
      # The same proof replayed is rejected by the production replay check.
      assert {:error, %{error_reason: :replay, scheme: :dpop}} = Verifier.verify_request(request)
    end
  end

  describe "request validation" do
    test "raises without a method or url" do
      assert_raise ArgumentError, fn -> Verifier.verify_request(url: @url, headers: []) end
      assert_raise ArgumentError, fn -> Verifier.verify_request(method: "GET", headers: []) end
    end

    test "verify_token: true without a config raises", ctx do
      proof = Fixture.proof(ctx.jwk, "GET", @url)

      assert_raise ArgumentError, fn ->
        Verifier.verify_request(method: "GET", url: @url, headers: [{"dpop", proof}], verify_token: true)
      end
    end
  end
end
