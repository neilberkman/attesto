defmodule Attesto.Parity.CrossLanguageParityTest do
  @moduledoc false
  # Cross-language CONTRACT parity: prove that artifacts Attesto produces
  # (and accepts) are bit-compatible with a reference Python stack
  # (joserfc + cryptography). This is an IN-PROCESS check: the `erlang_python`
  # `:py` NIF evaluates the Python directly inside the BEAM, with no live
  # HTTP endpoint involved. The three legs:
  #
  #   1. JWT verify: an Attesto-minted RS256 JWT verifies and decodes to
  #      the same claims under joserfc AND under a raw `cryptography`
  #      verifier (a second, decode-independent implementation), using the
  #      public PEM Attesto derives from the signing key.
  #   2. Thumbprint: the RFC 7638 JWK thumbprint Attesto computes for an
  #      EC P-256 key equals joserfc's thumbprint over the same JWK.
  #   3. DPoP proof: a DPoP proof JWS built entirely by Python (joserfc,
  #      ES256) verifies in Attesto.DPoP.verify_proof, and the verified
  #      `jkt` equals Python's own thumbprint of the signing key. This
  #      proves a real third-party Python client interoperates with the
  #      engine's proof verifier.
  #
  # The reference helpers live in `test/support/python/attesto_compat.py`,
  # driven through `Attesto.Test.PythonBridge`. The module self-skips when
  # the bridge runtime or the required Python packages are unavailable,
  # rather than failing the suite.

  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Test.PythonBridge

  @moduletag :parity

  # test/parity/cross_language_parity_test.exs -> test/support/python
  @python_lib_path Path.expand("../support/python", __DIR__)

  setup_all do
    case PythonBridge.availability() do
      :ok -> %{python: :ready}
      {:skip, reason} -> %{python: {:skip, reason}}
    end
  end

  setup %{python: python} do
    case python do
      :ready -> :ok
      {:skip, reason} -> {:ok, skip: "python parity stack unavailable: #{reason}"}
    end
  end

  describe "JWT verify parity (Attesto RS256 -> joserfc + cryptography)" do
    test "an Attesto-minted token decodes to identical claims in both Python verifiers", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      public_pem = Attesto.Key.public_pem(pem)

      {:ok, token} =
        Attesto.Token.mint(config, %{
          kind: "client",
          sub: "oc_live_parity",
          scopes: ["documents.read", "documents.write"],
          claims: %{"client_id" => "oc_live_parity"}
        })

      # joserfc leg.
      jose_claims =
        py_eval!("joserfc_verify_rs256(token, public_pem)", %{
          "public_pem" => public_pem,
          "token" => token.access_token
        })

      assert jose_claims["sub"] == "oc_live_parity"
      assert jose_claims["iss"] == "https://api.example.com/"
      assert jose_claims["scope"] == "documents.read documents.write"

      # cryptography leg: a decode-independent verifier enforcing iss/aud.
      crypto_claims =
        py_eval!("cryptography_verify_rs256(token, public_pem, issuer, audience)", %{
          "audience" => "https://api.example.com/",
          "issuer" => "https://api.example.com/",
          "public_pem" => public_pem,
          "token" => token.access_token
        })

      assert crypto_claims["sub"] == "oc_live_parity"
      assert crypto_claims["iss"] == "https://api.example.com/"
      assert crypto_claims["scope"] == "documents.read documents.write"

      # Both Python verifiers agree with each other and with Attesto's own
      # verifier on the load-bearing claims.
      {:ok, attesto_claims} = Attesto.Token.verify(config, token.access_token)

      for key <- ["sub", "iss", "scope"] do
        assert jose_claims[key] == crypto_claims[key]
        assert jose_claims[key] == attesto_claims[key]
      end
    end
  end

  describe "thumbprint parity (Attesto compute_jkt -> joserfc RFC 7638)" do
    test "an EC P-256 JWK yields the same RFC 7638 thumbprint in both stacks", _ctx do
      # Elixir is the source of the key here: generate a real EC P-256 key
      # and export its public JWK members, so both stacks thumbprint the
      # SAME jwk. (The DPoP-proof leg below exercises the Python -> Attesto
      # direction over a JWK embedded in a compact JWS, the real interop
      # path.)
      {_, public_jwk} = JOSE.JWK.to_public_map(JOSE.JWK.generate_key({:ec, "P-256"}))

      attesto_jkt = Attesto.DPoP.compute_jkt(public_jwk)
      python_jkt = py_eval!("joserfc_jwk_thumbprint(jwk)", %{"jwk" => public_jwk})

      assert Attesto.Thumbprint.valid?(attesto_jkt)
      assert attesto_jkt == python_jkt
    end
  end

  describe "DPoP proof parity (Python joserfc client -> Attesto verifier)" do
    test "a Python-built ES256 DPoP proof verifies in Attesto with the matching jkt", _ctx do
      htu = "https://api.example.com/oauth/token"
      iat = System.system_time(:second)
      jti = "parity-#{System.unique_integer([:positive])}"

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

      # The verified thumbprint Attesto returns is exactly the RFC 7638
      # thumbprint Python computed over the same signing key.
      assert verified.jkt == python_jkt
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
