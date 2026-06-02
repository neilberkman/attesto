defmodule Attesto.ClientAssertionTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.ClientAssertion

  @client_id "client-123"
  @audience "https://issuer.example/oauth/token"

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jwk, overrides \\ %{}) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, Map.merge(%{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256"}, overrides))
  end

  defp assertion(jwk, overrides \\ %{}) do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => @client_id,
          "sub" => @client_id,
          "aud" => @audience,
          "iat" => now,
          "exp" => now + 60,
          "jti" => "jti-" <> Integer.to_string(System.unique_integer([:positive]))
        },
        overrides
      )

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  test "verifies a valid private_key_jwt assertion against a trusted JWK" do
    key = ec_key()
    jwt = assertion(key)

    assert {:ok, claims} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [public_jwk(key)]})

    assert claims["iss"] == @client_id
    assert claims["sub"] == @client_id
  end

  test "rejects alg confusion: token header alg must match the trusted key alg" do
    key = ec_key()
    jwt = assertion(key)
    jwk = public_jwk(key, %{"alg" => "RS256"})

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [jwk]})
  end

  test "rejects wrong audience and missing jti" do
    key = ec_key()

    assert {:error, :invalid_audience} =
             key
             |> assertion(%{"aud" => "https://other.example/token"})
             |> ClientAssertion.verify(@client_id, @audience, %{"keys" => [public_jwk(key)]})

    assert {:error, :missing_jti} =
             key
             |> assertion(%{"jti" => ""})
             |> ClientAssertion.verify(@client_id, @audience, %{"keys" => [public_jwk(key)]})
  end

  test "peek_client_id reads iss without trusting the assertion" do
    key = ec_key()
    assert {:ok, @client_id} = ClientAssertion.peek_client_id(assertion(key))
  end

  test "rejects an RS256-signed assertion - FAPI 2 forbids RS256 for client auth" do
    key = JOSE.JWK.generate_key({:rsa, 2048})
    now = System.system_time(:second)

    claims = %{
      "iss" => @client_id,
      "sub" => @client_id,
      "aud" => @audience,
      "iat" => now,
      "exp" => now + 60,
      "jti" => "jti-rs256"
    }

    header = %{"alg" => "RS256", "kid" => JOSE.JWK.thumbprint(key)}
    {_header, jwt} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

    {_kty, jwk} = JOSE.JWK.to_public_map(key)
    jwk = Map.merge(jwk, %{"kid" => JOSE.JWK.thumbprint(key), "alg" => "RS256"})

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [jwk]})
  end
end
