defmodule Attesto.RequestObjectTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.RequestObject

  @client_id "client-123"
  @issuer @client_id
  @audience "https://issuer.example/authorize"

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jwk, overrides \\ %{}) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, Map.merge(%{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256"}, overrides))
  end

  defp request_object(jwk, claim_overrides \\ %{}, header_overrides \\ %{}) do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => @client_id,
          "client_id" => @client_id,
          "aud" => @audience,
          "iat" => now,
          "exp" => now + 300,
          "scope" => "openid"
        },
        claim_overrides
      )

    header = Map.merge(%{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}, header_overrides)
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp base_opts, do: [issuer: @issuer, audience: @audience]

  test "verifies a valid signed request object with default opts" do
    key = ec_key()
    jwt = request_object(key)

    assert {:ok, params} =
             RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())

    assert params["scope"] == "openid"
  end

  describe ":accepted_algs" do
    test "default rejects an RS256-signed object (FAPI 2 forbids RS256)" do
      key = JOSE.JWK.generate_key({:rsa, 2048})
      jwt = request_object(key, %{}, %{"alg" => "RS256", "kid" => JOSE.JWK.thumbprint(key)})
      jwk = public_jwk(key, %{"alg" => "RS256"})

      assert {:error, :invalid_signature} =
               RequestObject.verify(jwt, %{"keys" => [jwk]}, base_opts())
    end

    test "explicitly narrowing accepted_algs rejects an otherwise-accepted alg" do
      key = ec_key()
      jwt = request_object(key)

      assert {:error, :invalid_signature} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_algs: ["EdDSA"]]
               )
    end

    test "explicit accepted_algs that includes the key's alg still verifies" do
      key = ec_key()
      jwt = request_object(key)

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_algs: ["ES256"]]
               )
    end
  end

  describe ":require_nbf and :max_nbf_age_seconds" do
    test "default accepts an object without nbf" do
      key = ec_key()
      jwt = request_object(key)

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "require_nbf rejects an object without nbf" do
      key = ec_key()
      jwt = request_object(key)

      assert {:error, :not_yet_valid} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_nbf: true]
               )
    end

    test "require_nbf accepts an object that carries nbf" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now})

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_nbf: true]
               )
    end

    test "max_nbf_age_seconds rejects an nbf older than the bound" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now - 600})

      assert {:error, :not_yet_valid} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_nbf_age_seconds: 60, now: now]
               )
    end

    test "default ignores a stale nbf (lenient JAR behaviour preserved)" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now - 600})

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts() ++ [now: now])
    end
  end

  describe ":require_exp and :max_lifetime_seconds" do
    test "default accepts an object without exp" do
      key = ec_key()
      jwt = sign_without(key, "exp")

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "require_exp rejects an object without exp" do
      key = ec_key()
      jwt = sign_without(key, "exp")

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_exp: true]
               )
    end

    test "max_lifetime_seconds rejects exp beyond nbf + N" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now, "exp" => now + 3600})

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_lifetime_seconds: 60, now: now]
               )
    end

    test "max_lifetime_seconds accepts exp within nbf + N" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now, "exp" => now + 30})

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_lifetime_seconds: 60, now: now]
               )
    end

    test "default ignores a long lifetime (lenient JAR behaviour preserved)" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now, "exp" => now + 3600})

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts() ++ [now: now])
    end
  end

  describe ":accepted_typ" do
    test "default accepts any typ including absence" do
      key = ec_key()
      jwt = request_object(key)
      jwt_with_typ = request_object(key, %{}, %{"typ" => "oauth-authz-req+jwt"})
      jwt_no_typ = request_object_without_typ(key)

      assert {:ok, _} = RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())

      assert {:ok, _} =
               RequestObject.verify(jwt_with_typ, %{"keys" => [public_jwk(key)]}, base_opts())

      assert {:ok, _} =
               RequestObject.verify(jwt_no_typ, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "accepted_typ list requires the header typ to match" do
      key = ec_key()
      jwt = request_object(key, %{}, %{"typ" => "oauth-authz-req+jwt"})

      assert {:ok, _} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )
    end

    test "accepted_typ list rejects a non-member typ" do
      key = ec_key()
      jwt = request_object(key, %{}, %{"typ" => "JWT"})

      assert {:error, :invalid_typ} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )
    end

    test "accepted_typ rejects an absent typ unless nil is a member" do
      key = ec_key()
      jwt = request_object_without_typ(key)

      assert {:error, :invalid_typ} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )

      assert {:ok, _} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt", nil]]
               )
    end
  end

  # Helpers that build a signed object lacking a given claim entirely.
  defp sign_without(jwk, claim) do
    now = System.system_time(:second)

    claims =
      %{
        "iss" => @client_id,
        "client_id" => @client_id,
        "aud" => @audience,
        "iat" => now,
        "exp" => now + 300,
        "scope" => "openid"
      }
      |> Map.delete(claim)

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  # JOSE.JWT.sign injects `typ: "JWT"`; JOSE.JWS.sign leaves the protected
  # header exactly as given, letting us produce an object with no `typ`.
  defp request_object_without_typ(jwk) do
    now = System.system_time(:second)

    payload =
      JSON.encode!(%{
        "iss" => @client_id,
        "client_id" => @client_id,
        "aud" => @audience,
        "iat" => now,
        "exp" => now + 300,
        "scope" => "openid"
      })

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_meta, compact} = jwk |> JOSE.JWS.sign(payload, header) |> JOSE.JWS.compact()
    compact
  end
end
