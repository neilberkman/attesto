defmodule Attesto.JARMTest do
  @moduledoc false
  # Factory.config installs key material into the application env, so these are
  # not async-safe.
  use ExUnit.Case, async: false

  alias Attesto.JARM
  alias Attesto.Key
  alias Attesto.SigningAlg
  alias Attesto.Test.Factory

  setup do
    {:ok, config: Factory.config(Factory.rsa_pem())}
  end

  # Verify the JARM JWT the way a client would: strictly, against the AS's
  # signing key and pinned algorithm, returning the claims.
  defp verify(config, jwt) do
    pem = config.keystore.signing_pem()
    jwk = Key.jwk(pem)
    alg = SigningAlg.for_key(config.keystore, pem, signing?: true)

    assert {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} =
             JOSE.JWT.verify_strict(jwk, [alg], jwt)

    claims
  end

  defp header(jwt) do
    jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()
  end

  test "signs a success response with iss/aud/exp/iat and the response params", %{config: config} do
    now = 1_700_000_000

    {:ok, jwt} =
      JARM.response_jwt(
        config,
        "client-123",
        %{"code" => "abc", "state" => "xyz", "iss" => config.issuer},
        now: now
      )

    claims = verify(config, jwt)

    # JARM §2.1 JWT claims.
    assert claims["iss"] == config.issuer
    assert claims["aud"] == "client-123"
    assert claims["iat"] == now
    assert claims["exp"] == now + 600
    # The authorization-response parameters ride as top-level claims.
    assert claims["code"] == "abc"
    assert claims["state"] == "xyz"
  end

  test "signs an error response (no code), addressed to the client", %{config: config} do
    {:ok, jwt} =
      JARM.response_jwt(config, "client-123", %{
        "error" => "access_denied",
        "error_description" => "user denied",
        "state" => "xyz"
      })

    claims = verify(config, jwt)

    assert claims["error"] == "access_denied"
    assert claims["error_description"] == "user denied"
    assert claims["state"] == "xyz"
    assert claims["aud"] == "client-123"
    refute Map.has_key?(claims, "code")
  end

  test "drops nil response params rather than emitting null claims", %{config: config} do
    {:ok, jwt} = JARM.response_jwt(config, "c", %{"code" => "abc", "state" => nil})
    claims = verify(config, jwt)

    assert claims["code"] == "abc"
    refute Map.has_key?(claims, "state")
  end

  test ":lifetime may only shorten the default", %{config: config} do
    now = 1_700_000_000

    {:ok, short} = JARM.response_jwt(config, "c", %{"code" => "a"}, now: now, lifetime: 60)
    assert verify(config, short)["exp"] == now + 60

    {:ok, capped} = JARM.response_jwt(config, "c", %{"code" => "a"}, now: now, lifetime: 99_999)
    assert verify(config, capped)["exp"] == now + 600
  end

  test "pins a real signing algorithm in the JOSE header (never none)", %{config: config} do
    {:ok, jwt} = JARM.response_jwt(config, "c", %{"code" => "a"})
    %{"alg" => alg, "kid" => kid} = header(jwt)

    assert alg in ~w(RS256 PS256 ES256 EdDSA)
    assert is_binary(kid) and kid != ""
  end
end
