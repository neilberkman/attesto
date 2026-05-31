defmodule Attesto.IDTokenPropertyTest do
  @moduledoc false
  # Direct properties for the OIDC ID-token primitive. These stay below the
  # provider layer: no endpoint, login, or consent assumptions.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Attesto.IDToken
  alias Attesto.Test.Factory

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem)}
  end

  describe "mint/4 then verify/3" do
    property "round-trips generated subjects, clients, nonces, and shorter lifetimes", %{config: config} do
      check all(
              subject_suffix <- suffix_generator(),
              client_suffix <- suffix_generator(),
              nonce <- nonce_generator(),
              lifetime <- integer(1..3_600),
              now <- integer(1_700_000_000..1_700_100_000),
              max_runs: 80
            ) do
        subject = "usr_" <> subject_suffix
        client_id = "client-" <> client_suffix

        assert {:ok, id_token} =
                 IDToken.mint(config, subject, client_id,
                   nonce: nonce,
                   lifetime: lifetime,
                   now: now,
                   extra_claims: %{"email" => subject_suffix <> "@example.test"}
                 )

        assert {:ok, claims} =
                 IDToken.verify(config, id_token, client_id: client_id, nonce: nonce, now: now)

        assert claims["iss"] == config.issuer
        assert claims["sub"] == subject
        assert claims["aud"] == client_id
        assert claims["nonce"] == nonce
        assert claims["email"] == subject_suffix <> "@example.test"
        assert claims["iat"] == now
        assert claims["exp"] == now + lifetime
        refute Map.has_key?(claims, "scope")
      end
    end

    property "lifetime can only shorten the default", %{config: config} do
      check all(
              subject_suffix <- suffix_generator(),
              client_suffix <- suffix_generator(),
              requested_lifetime <- one_of([integer(3_601..100_000), integer(-100..0)]),
              now <- integer(1_700_000_000..1_700_100_000),
              max_runs: 60
            ) do
        subject = "usr_" <> subject_suffix
        client_id = "client-" <> client_suffix

        assert {:ok, id_token} =
                 IDToken.mint(config, subject, client_id, lifetime: requested_lifetime, now: now)

        assert {:ok, claims} = IDToken.verify(config, id_token, client_id: client_id, now: now)
        assert claims["exp"] - claims["iat"] == 3_600
      end
    end
  end

  describe "verification boundary" do
    property "any single-byte mutation of a minted ID token is rejected", %{config: config} do
      subject = "usr_mutation"
      client_id = "client-mutation"
      now = 1_700_000_000

      {:ok, id_token} = IDToken.mint(config, subject, client_id, now: now)
      size = byte_size(id_token)

      check all(
              pos <- integer(0..(size - 1)),
              flip <- integer(1..255),
              max_runs: 300
            ) do
        mutated = flip_byte(id_token, pos, flip)

        if mutated != id_token do
          assert match?({:error, _}, IDToken.verify(config, mutated, client_id: client_id, now: now)),
                 "byte flip at #{pos} unexpectedly verified"
        end
      end
    end

    property "reserved OIDC claims cannot be shadowed by extra_claims", %{config: config} do
      check all(
              reserved <- member_of(~w(iss sub aud exp iat nonce azp auth_time acr amr at_hash c_hash)),
              subject_suffix <- suffix_generator(),
              client_suffix <- suffix_generator(),
              max_runs: 80
            ) do
        assert {:error, :reserved_claim_conflict} =
                 IDToken.mint(config, "usr_" <> subject_suffix, "client-" <> client_suffix,
                   extra_claims: %{reserved => "shadow"}
                 )
      end
    end
  end

  defp suffix_generator do
    gen all(chars <- list_of(member_of(Enum.concat([?a..?z, ?0..?9])), min_length: 1, max_length: 16)) do
      List.to_string(chars)
    end
  end

  defp nonce_generator do
    gen all(chars <- list_of(member_of(Enum.concat([?A..?Z, ?a..?z, ?0..?9, [?-, ?_]])), min_length: 1, max_length: 32)) do
      List.to_string(chars)
    end
  end

  defp flip_byte(binary, pos, xor) do
    <<head::binary-size(^pos), byte, rest::binary>> = binary
    <<head::binary, Bitwise.bxor(byte, xor), rest::binary>>
  end
end
