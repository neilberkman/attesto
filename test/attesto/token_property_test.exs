defmodule Attesto.TokenPropertyTest do
  @moduledoc false
  # Lifecycle properties for Attesto.Token. These sit beside the targeted
  # example tests and assert broad mint/verify invariants over generated
  # principals, scopes, clocks, lifetimes, and sender constraints.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Attesto.Secret
  alias Attesto.Test.Factory
  alias Attesto.Token

  @client_scopes ~w(documents.read documents.write reports.read webhooks.admin)
  @user_scopes ~w(profile.read email.read sessions.read)

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem)}
  end

  describe "mint/3 then verify/3" do
    property "round-trips generated client principals and canonicalizes scope order", %{config: config} do
      check all(
              suffix <- suffix_generator(),
              scopes <- list_of(member_of(@client_scopes), max_length: 8),
              now <- integer(1_700_000_000..1_700_100_000),
              lifetime <- integer(1..1_800),
              max_runs: 80
            ) do
        sub = "oc_" <> suffix

        principal = %{
          kind: "client",
          sub: sub,
          scopes: scopes,
          claims: %{"client_id" => sub}
        }

        assert {:ok, token} = Token.mint(config, principal, now: now, lifetime: lifetime)
        assert {:ok, claims} = Token.verify(config, token.access_token, now: now)

        expected_scopes = Enum.uniq(scopes)
        expected_scope_string = Enum.join(expected_scopes, " ")
        expected_lifetime = min(lifetime, Token.default_lifetime_seconds(config))

        assert token.token_type == "Bearer"
        assert token.scope == expected_scope_string
        assert token.expires_in == expected_lifetime
        assert claims["sub"] == sub
        assert claims["client_id"] == sub
        assert claims["scope"] == expected_scope_string
        assert claims["iat"] == now
        assert claims["exp"] == now + expected_lifetime
        assert claims["typ"] == "access"
        assert claims["principal_kind"] == "client"
      end
    end

    property "round-trips generated user principals with required identity claims", %{config: config} do
      check all(
              suffix <- suffix_generator(),
              scopes <- list_of(member_of(@user_scopes), max_length: 6),
              act <- suffix_generator(),
              sid <- suffix_generator(),
              token_version <- integer(0..10_000),
              now <- integer(1_700_000_000..1_700_100_000),
              max_runs: 80
            ) do
        sub = "usr_" <> suffix

        principal = %{
          kind: "user",
          sub: sub,
          scopes: scopes,
          claims: %{
            "act" => "ac_" <> act,
            "sid" => "sess_" <> sid,
            "token_version" => token_version
          }
        }

        assert {:ok, token} = Token.mint(config, principal, now: now)
        assert {:ok, claims} = Token.verify(config, token.access_token, now: now)

        expected_scope_string = scopes |> Enum.uniq() |> Enum.join(" ")

        assert token.scope == expected_scope_string
        assert claims["sub"] == sub
        assert claims["act"] == "ac_" <> act
        assert claims["sid"] == "sess_" <> sid
        assert claims["token_version"] == token_version
        assert claims["scope"] == expected_scope_string
        assert claims["principal_kind"] == "user"
      end
    end

    property "verification respects the sender-constraint binding matrix", %{config: config} do
      check all(
              suffix <- suffix_generator(),
              binding <- member_of([:none, :dpop, :mtls]),
              now <- integer(1_700_000_000..1_700_100_000),
              max_runs: 60
            ) do
        sub = "oc_" <> suffix

        principal = %{
          kind: "client",
          sub: sub,
          scopes: ["documents.read"],
          claims: %{"client_id" => sub}
        }

        dpop_jkt = Secret.hash("dpop-" <> suffix)
        mtls_thumbprint = Secret.hash("mtls-" <> suffix)

        {mint_opts, good_verify_opts} =
          case binding do
            :none ->
              {[now: now], [now: now]}

            :dpop ->
              {[now: now, dpop_jkt: dpop_jkt], [now: now, dpop_jkt: dpop_jkt]}

            :mtls ->
              {[now: now, mtls_cert_thumbprint: mtls_thumbprint], [now: now, mtls_cert_thumbprint: mtls_thumbprint]}
          end

        assert {:ok, token} = Token.mint(config, principal, mint_opts)
        assert {:ok, _claims} = Token.verify(config, token.access_token, good_verify_opts)

        case binding do
          :none ->
            assert {:error, :dpop_proof_unexpected} =
                     Token.verify(config, token.access_token, now: now, dpop_jkt: dpop_jkt)

            assert {:error, :mtls_cert_unexpected} =
                     Token.verify(config, token.access_token, now: now, mtls_cert_thumbprint: mtls_thumbprint)

          :dpop ->
            assert token.token_type == "DPoP"
            assert {:error, :dpop_proof_required} = Token.verify(config, token.access_token, now: now)

            assert {:error, :dpop_binding_mismatch} =
                     Token.verify(config, token.access_token, now: now, dpop_jkt: Secret.hash("other-" <> suffix))

            assert {:error, :mtls_cert_unexpected} =
                     Token.verify(config, token.access_token, now: now, mtls_cert_thumbprint: mtls_thumbprint)

          :mtls ->
            assert token.token_type == "Bearer"
            assert {:error, :mtls_cert_required} = Token.verify(config, token.access_token, now: now)

            assert {:error, :mtls_binding_mismatch} =
                     Token.verify(config, token.access_token,
                       now: now,
                       mtls_cert_thumbprint: Secret.hash("other-" <> suffix)
                     )

            assert {:error, :dpop_proof_unexpected} =
                     Token.verify(config, token.access_token, now: now, dpop_jkt: dpop_jkt)
        end
      end
    end
  end

  describe "mint/3 rejection properties" do
    property "reserved claim names can never be shadowed by extra principal claims", %{config: config} do
      check all(
              reserved <- member_of(~w(iss aud exp iat jti sub scope typ cnf principal_kind)),
              suffix <- suffix_generator(),
              max_runs: 80
            ) do
        sub = "oc_" <> suffix
        claims = Map.put(%{"client_id" => sub}, reserved, "shadow")

        assert {:error, :reserved_claim_conflict} =
                 Token.mint(config, %{kind: "client", sub: sub, scopes: [], claims: claims})
      end
    end
  end

  defp suffix_generator do
    gen all(chars <- list_of(member_of(Enum.concat([?a..?z, ?0..?9])), min_length: 1, max_length: 16)) do
      List.to_string(chars)
    end
  end
end
