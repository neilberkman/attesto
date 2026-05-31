defmodule Attesto.Parity.FullDanceParityTest do
  @moduledoc false
  # Cross-language CONTRACT parity for the WHOLE authorization-code grant
  # dance, with a real third-party Python client (joserfc + cryptography) on
  # one side and Attesto as the server on the other. Where the sibling
  # CrossLanguageParityTest proves single artifacts (a standalone JWT, a
  # thumbprint, one DPoP proof) interoperate, this test drives the full
  # sequence and asserts every hop lines up across the language boundary:
  #
  #   1. PKCE: Python computes the RFC 7636 §4.1/§4.2 S256 transform with
  #      stdlib (`os.urandom` + `hashlib.sha256` + base64url-no-pad),
  #      generating a `code_verifier` and its `S256` `code_challenge` the
  #      way a real client library does. Attesto's `PKCE.challenge/1` over
  #      the SAME verifier yields the SAME challenge, so the two stacks
  #      agree on the binding value before a code is ever minted.
  #   2. Authorization code: Attesto issues a single-use code bound to that
  #      challenge.
  #   3. Redemption: the verifier is presented and Attesto's `redeem/4`
  #      returns a Grant.
  #   4. Access token: Attesto mints an RS256 user access token from the
  #      Grant, and BOTH Python verifiers (joserfc and a raw `cryptography`
  #      verifier) check its signature and decode its claims, agreeing with
  #      Attesto's own verifier on the load-bearing claims.
  #   5. Refresh rotation: Attesto issues a refresh token, rotates it once
  #      (successor is generation 1), and a replay outside the idempotency
  #      window trips `:reuse_detected` and revokes the family.
  #   6. DPoP: Python (joserfc, ES256) builds a DPoP proof; Attesto's
  #      `verify_proof/2` accepts it and the verified `jkt` equals Python's
  #      own RFC 7638 thumbprint of the proof key.
  #
  # This is an IN-PROCESS check via the `erlang_python` `:py` NIF, with no
  # live HTTP endpoint. The reference helpers live in
  # `test/support/python/attesto_compat.py`, driven through
  # `Attesto.Test.PythonBridge`. The module self-skips when the bridge
  # runtime or the required Python packages are unavailable.

  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.CodeStore
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Test.Factory
  alias Attesto.Test.PythonBridge

  @moduletag :parity

  # test/parity/full_dance_parity_test.exs -> test/support/python
  @python_lib_path Path.expand("../support/python", __DIR__)

  setup_all do
    case PythonBridge.availability() do
      :ok -> %{python: :ready}
      {:skip, reason} -> %{python: {:skip, reason}}
    end
  end

  setup %{python: python} do
    # The named-singleton stores carry per-test state (issued codes, refresh
    # families). Start them fresh under the test supervisor so each test sees
    # an empty store; async is already false for the whole module.
    start_supervised!(CodeStore.ETS)
    start_supervised!(RefreshStore.ETS)

    case python do
      :ready -> :ok
      {:skip, reason} -> {:ok, skip: "python parity stack unavailable: #{reason}"}
    end
  end

  describe "full authorization-code dance (Python client <-> Attesto server)" do
    test "PKCE, code redemption, token mint, refresh rotation, and DPoP all interoperate", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      public_pem = Attesto.Key.public_pem(pem)

      client_id = "oc_full_dance"
      redirect_uri = "https://client.example.com/callback"
      subject = "usr_full_dance"
      scopes = ["documents.read", "documents.write"]

      # ----- 1. PKCE: Python generates the verifier + S256 challenge, and
      # Attesto agrees on the challenge for the SAME verifier. -----
      {code_verifier, python_challenge} = py_eval!("generate_pkce_pair()", %{})

      assert Attesto.PKCE.valid_verifier?(code_verifier)
      assert {:ok, attesto_challenge} = Attesto.PKCE.challenge(code_verifier)
      assert attesto_challenge == python_challenge
      assert Attesto.PKCE.valid_challenge?(python_challenge)

      # ----- 2. Attesto issues an auth code bound to the challenge. -----
      assert {:ok, code} =
               AuthorizationCode.issue(CodeStore.ETS, %{
                 client_id: client_id,
                 redirect_uri: redirect_uri,
                 code_challenge: python_challenge,
                 subject: subject,
                 scope: scopes
               })

      # ----- 3. Present the verifier; Attesto redeems -> Grant. The
      # presented :client_id MUST match the stored context. -----
      assert {:ok, grant} =
               AuthorizationCode.redeem(CodeStore.ETS, code, %{
                 redirect_uri: redirect_uri,
                 code_verifier: code_verifier,
                 client_id: client_id
               })

      assert %AuthorizationCode.Grant{} = grant
      assert grant.client_id == client_id
      assert grant.subject == subject
      assert grant.scope == scopes

      # The code is single-use: a second redemption (even valid) fails.
      assert {:error, :invalid_grant} =
               AuthorizationCode.redeem(CodeStore.ETS, code, %{
                 redirect_uri: redirect_uri,
                 code_verifier: code_verifier,
                 client_id: client_id
               })

      # ----- 4. Attesto mints a user access token from the grant; both
      # Python verifiers check the RS256 claims. The "user" principal kind
      # requires act/sid/token_version and a usr_ subject prefix. -----
      assert {:ok, token} =
               Attesto.Token.mint(config, %{
                 kind: "user",
                 sub: grant.subject,
                 scopes: grant.scope,
                 claims: %{
                   "act" => client_id,
                   "sid" => "sess_full_dance",
                   "token_version" => 0
                 }
               })

      assert Attesto.Token.signing_alg() == "RS256"

      jose_claims =
        py_eval!("joserfc_verify_rs256(token, public_pem)", %{
          "public_pem" => public_pem,
          "token" => token.access_token
        })

      assert jose_claims["sub"] == subject
      assert jose_claims["iss"] == "https://api.example.com/"
      assert jose_claims["scope"] == "documents.read documents.write"

      crypto_claims =
        py_eval!("cryptography_verify_rs256(token, public_pem, issuer, audience)", %{
          "audience" => "https://api.example.com/",
          "issuer" => "https://api.example.com/",
          "public_pem" => public_pem,
          "token" => token.access_token
        })

      assert crypto_claims["sub"] == subject
      assert crypto_claims["iss"] == "https://api.example.com/"
      assert crypto_claims["scope"] == "documents.read documents.write"

      {:ok, attesto_claims} = Attesto.Token.verify(config, token.access_token)

      for key <- ["sub", "iss", "aud", "scope"] do
        assert jose_claims[key] == crypto_claims[key]
        assert jose_claims[key] == attesto_claims[key]
      end

      # ----- 5. Refresh token: issue, rotate once (successor is generation
      # 1), then replay the original outside the idempotency window ->
      # :reuse_detected. -----
      assert {:ok, issued} =
               RefreshToken.issue(RefreshStore.ETS, %{
                 subject: grant.subject,
                 scope: grant.scope,
                 client_id: client_id
               })

      assert issued.generation == 0

      assert {:ok, rotated} =
               RefreshToken.rotate(RefreshStore.ETS, issued.token, client_id: client_id)

      assert rotated.generation == 1
      assert rotated.family_id == issued.family_id
      assert rotated.context.subject == grant.subject
      assert rotated.context.scope == grant.scope
      assert rotated.token != issued.token

      # Replaying the original outside the short idempotency window is the
      # captured-token signal: the whole family is revoked.
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, issued.token,
                 client_id: client_id,
                 rotation_grace_seconds: 0
               )

      # Family revocation means the previously-valid successor is dead too.
      assert {:error, :invalid_grant} =
               RefreshToken.rotate(RefreshStore.ETS, rotated.token, client_id: client_id)

      # ----- 6. DPoP: Python builds an ES256 proof, Attesto verifies it,
      # and the verified jkt equals Python's RFC 7638 thumbprint. -----
      htu = "https://api.example.com/oauth/token"
      iat = System.system_time(:second)
      jti = "full-dance-#{System.unique_integer([:positive])}"

      {proof, _public_jwk, python_jkt} =
        py_eval!("build_es256_dpop_proof(htm, htu, iat, jti)", %{
          "htm" => "POST",
          "htu" => htu,
          "iat" => iat,
          "jti" => jti
        })

      assert {:ok, verified} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "POST",
                 http_uri: htu,
                 now: iat
               )

      assert verified.jkt == python_jkt
      assert Attesto.Thumbprint.valid?(verified.jkt)
      assert verified.htm == "POST"
      assert verified.htu == htu
      assert verified.jti == jti
      assert verified.iat == iat
    end
  end

  # Evaluate `attesto_compat.<expr>` through the bridge with the module
  # directory on sys.path, decoding the result back to Elixir terms.
  defp py_eval!(expr, bindings) do
    PythonBridge.eval_wrapped!("__import__('attesto_compat').#{expr}", bindings, paths: [@python_lib_path])
  end
end
