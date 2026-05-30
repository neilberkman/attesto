defmodule Attesto.PropertyTest do
  @moduledoc false
  # Property-based coverage for the pure shape/algebra primitives plus a
  # mutation-fuzz over minted-token verification. The mutation-fuzz mints
  # real tokens via Factory.config/2, which installs the signing PEM into
  # the global Attesto.Keystore.Static app env, so the whole module runs
  # serially.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Attesto.DPoP
  alias Attesto.PKCE
  alias Attesto.Scope
  alias Attesto.Test.Factory
  alias Attesto.Thumbprint
  alias Attesto.Token

  @thumbprint_length 43
  @base64url_no_pad ~r/\A[A-Za-z0-9_-]{43}\z/

  # RFC 7636 §4.1 unreserved verifier alphabet.
  @verifier_chars Enum.concat([?A..?Z, ?a..?z, ?0..?9, [?-, ?., ?_, ?~]])

  # A small, fixed scope catalog with two resources so resource-level
  # wildcards have something to match and miss.
  @catalog_scopes ~w(
    documents.read documents.write
    webhooks.read webhooks.write webhooks.admin
  )

  # ----------------------------------------------------------------------
  # (1) Attesto.Thumbprint.of/1 totality and round-trip.
  # ----------------------------------------------------------------------

  describe "Thumbprint.of/1" do
    property "over any binary returns a 43-char base64url-no-pad value that valid?/1 accepts" do
      check all(bytes <- binary()) do
        thumb = Thumbprint.of(bytes)

        assert is_binary(thumb)
        assert String.length(thumb) == @thumbprint_length
        assert byte_size(thumb) == @thumbprint_length
        assert Regex.match?(@base64url_no_pad, thumb)
        assert Thumbprint.valid?(thumb)
      end
    end

    property "is deterministic for a given input" do
      check all(bytes <- binary()) do
        assert Thumbprint.of(bytes) == Thumbprint.of(bytes)
      end
    end

    property "valid?/1 rejects 43-char strings with an illegal character" do
      # Splice a non-alphabet character into an otherwise-valid thumbprint
      # at a random position, keeping the length at 43.
      check all(
              bytes <- binary(),
              pos <- integer(0..(@thumbprint_length - 1))
            ) do
        thumb = Thumbprint.of(bytes)
        tampered = replace_at(thumb, pos, "!")

        assert String.length(tampered) == @thumbprint_length
        refute Thumbprint.valid?(tampered)
      end
    end
  end

  # ----------------------------------------------------------------------
  # (2) Attesto.DPoP.compute_ath/1 totality (it delegates to Thumbprint.of).
  # ----------------------------------------------------------------------

  describe "DPoP.compute_ath/1" do
    property "over any access-token binary returns a valid 43-char thumbprint" do
      check all(token <- binary()) do
        ath = DPoP.compute_ath(token)

        assert is_binary(ath)
        assert String.length(ath) == @thumbprint_length
        assert Regex.match?(@base64url_no_pad, ath)
        assert Thumbprint.valid?(ath)
      end
    end

    property "agrees with Thumbprint.of/1 (ath is base64url(SHA-256(token)))" do
      check all(token <- binary()) do
        assert DPoP.compute_ath(token) == Thumbprint.of(token)
      end
    end
  end

  # ----------------------------------------------------------------------
  # (3) PKCE: well-formed verifiers round-trip; malformed ones are rejected.
  # ----------------------------------------------------------------------

  describe "PKCE" do
    property "a well-formed verifier (43..128 unreserved chars) challenges and verifies" do
      check all(verifier <- verifier_generator()) do
        assert PKCE.valid_verifier?(verifier)
        assert {:ok, challenge} = PKCE.challenge(verifier)

        # The challenge is itself a canonical S256 thumbprint.
        assert PKCE.valid_challenge?(challenge)
        assert Thumbprint.valid?(challenge)

        # And it verifies against the originating verifier (default S256).
        assert PKCE.verify(challenge, verifier) == :ok
      end
    end

    property "a verifier outside the length range is rejected" do
      check all(verifier <- out_of_range_verifier_generator()) do
        refute PKCE.valid_verifier?(verifier)
        assert PKCE.challenge(verifier) == {:error, :invalid_verifier}
      end
    end

    property "a length-valid verifier containing a disallowed character is rejected" do
      check all(verifier <- bad_char_verifier_generator()) do
        refute PKCE.valid_verifier?(verifier)
        assert PKCE.challenge(verifier) == {:error, :invalid_verifier}
      end
    end

    property "verify/3 rejects a presented verifier that does not match the challenge" do
      check all(
              real <- verifier_generator(),
              other <- verifier_generator(),
              real != other
            ) do
        {:ok, challenge} = PKCE.challenge(real)
        # Both are well-formed verifiers, so a different one is a mismatch,
        # never an :invalid_verifier.
        assert PKCE.verify(challenge, other) == {:error, :mismatch}
      end
    end

    property "verify/3 rejects any method other than S256" do
      check all(
              verifier <- verifier_generator(),
              method <- member_of(["plain", "S384", "s256", "", "RS256"])
            ) do
        {:ok, challenge} = PKCE.challenge(verifier)
        assert PKCE.verify(challenge, verifier, method) == {:error, :unsupported_method}
      end
    end
  end

  # ----------------------------------------------------------------------
  # (4) Scope.grants?/3 algebra over a random catalog and granted set.
  # ----------------------------------------------------------------------

  describe "Scope.grants?/3" do
    property "a catalog entry is granted IFF granted covers it (concrete, <resource>.*, or *)" do
      check all(
              granted <- granted_generator(),
              required <- member_of(@catalog_scopes)
            ) do
        catalog = Scope.new_catalog(@catalog_scopes)
        resource = required |> String.split(".", parts: 2) |> hd()

        # Independent recomputation of the grant rule from the granted set.
        expected =
          required in granted or
            "#{resource}.*" in granted or
            "*" in granted

        assert Scope.grants?(catalog, granted, required) == expected
      end
    end

    property "an uncatalogued required scope is never granted, even by *" do
      check all(
              granted <- granted_generator(),
              required <- uncatalogued_scope_generator()
            ) do
        catalog = Scope.new_catalog(@catalog_scopes)

        # Build a granted set that definitely includes the full wildcard
        # and a matching resource wildcard, to prove neither broadens past
        # the catalog.
        resource = required |> String.split(".", parts: 2) |> hd()
        loaded = ["*", "#{resource}.*" | granted]

        refute Scope.grants?(catalog, loaded, required)
      end
    end

    property "a wildcard form passed as the required scope is never granted" do
      check all(
              granted <- granted_generator(),
              required <- member_of(["*", "documents.*", "webhooks.*"])
            ) do
        catalog = Scope.new_catalog(@catalog_scopes)
        # Even granting everything, a wildcard *requirement* is ambiguous
        # and rejected.
        refute Scope.grants?(catalog, ["*" | granted], required)
      end
    end

    property "a nil or empty granted list never grants anything" do
      check all(
              required <- member_of(@catalog_scopes),
              granted <- member_of([nil, []])
            ) do
        catalog = Scope.new_catalog(@catalog_scopes)
        refute Scope.grants?(catalog, granted, required)
      end
    end
  end

  # ----------------------------------------------------------------------
  # (5) MUTATION-FUZZ: any single-byte mutation, truncation, or segment
  #     swap of a valid compact JWS must fail Token.verify (never {:ok, _}).
  # ----------------------------------------------------------------------

  describe "Token.verify mutation-fuzz" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)

      now = 1_700_000_000

      principal = %{
        kind: "client",
        sub: "oc_fuzz",
        scopes: ["documents.read"],
        claims: %{"client_id" => "oc_fuzz"}
      }

      {:ok, %{access_token: jwt}} = Token.mint(config, principal, now: now)

      # Sanity: the pristine token verifies under the same clock.
      assert {:ok, _claims} = Token.verify(config, jwt, now: now)

      {:ok, config: config, jwt: jwt, now: now}
    end

    property "flipping any single byte of the compact JWS is rejected", %{
      config: config,
      jwt: jwt,
      now: now
    } do
      size = byte_size(jwt)

      check all(
              pos <- integer(0..(size - 1)),
              flip <- integer(1..255),
              max_runs: 400
            ) do
        mutated = flip_byte(jwt, pos, flip)

        # A flip that lands on a value-preserving position (none, since we
        # XOR a non-zero flip) would equal the original; guard anyway.
        if mutated != jwt do
          assert match?({:error, _}, Token.verify(config, mutated, now: now)),
                 "byte flip at #{pos} (xor #{flip}) unexpectedly verified"
        end
      end
    end

    property "truncating the token to any shorter prefix is rejected", %{
      config: config,
      jwt: jwt,
      now: now
    } do
      size = byte_size(jwt)

      check all(len <- integer(0..(size - 1))) do
        truncated = binary_part(jwt, 0, len)
        assert match?({:error, _}, Token.verify(config, truncated, now: now))
      end
    end

    property "appending trailing bytes to the token is rejected", %{
      config: config,
      jwt: jwt,
      now: now
    } do
      check all(suffix <- binary(min_length: 1, max_length: 8)) do
        assert match?({:error, _}, Token.verify(config, jwt <> suffix, now: now))
      end
    end

    test "swapping any two of the three compact segments is rejected", %{
      config: config,
      jwt: jwt,
      now: now
    } do
      [h, p, s] = String.split(jwt, ".")

      swaps = [
        Enum.join([p, h, s], "."),
        Enum.join([s, p, h], "."),
        Enum.join([h, s, p], ".")
      ]

      for swapped <- swaps, swapped != jwt do
        assert match?({:error, _}, Token.verify(config, swapped, now: now)),
               "segment swap #{inspect(swapped)} unexpectedly verified"
      end
    end

    test "duplicating or dropping a dot-separated segment is rejected", %{
      config: config,
      jwt: jwt,
      now: now
    } do
      [h, p, s] = String.split(jwt, ".")

      malformed = [
        Enum.join([h, p], "."),
        Enum.join([h, p, s, s], "."),
        Enum.join([h, p, s, ""], "."),
        h <> "." <> p,
        "." <> jwt
      ]

      for token <- malformed do
        assert match?({:error, _}, Token.verify(config, token, now: now)),
               "malformed segmentation #{inspect(token)} unexpectedly verified"
      end
    end
  end

  # ----------------------------------------------------------------------
  # Generators and small helpers.
  # ----------------------------------------------------------------------

  # A well-formed RFC 7636 verifier: 43..128 chars from the unreserved set.
  defp verifier_generator do
    gen all(
          length <- integer(43..128),
          chars <- list_of(member_of(@verifier_chars), length: length)
        ) do
      List.to_string(chars)
    end
  end

  # A verifier-shaped string of the right alphabet but wrong length
  # (too short: 0..42, or too long: 129..200).
  defp out_of_range_verifier_generator do
    gen all(
          length <- one_of([integer(0..42), integer(129..200)]),
          chars <- list_of(member_of(@verifier_chars), length: length)
        ) do
      List.to_string(chars)
    end
  end

  # A length-valid (43..128) string that contains at least one character
  # outside the unreserved set, so only the alphabet check can fail it.
  defp bad_char_verifier_generator do
    gen all(
          length <- integer(43..128),
          good <- list_of(member_of(@verifier_chars), length: length),
          bad <- member_of([?/, ?+, ?=, ?\s, ?%, ?!, ?:, ?@, ?#]),
          pos <- integer(0..(length - 1))
        ) do
      good
      |> List.replace_at(pos, bad)
      |> List.to_string()
    end
  end

  # A random granted set drawn from the catalog plus the two wildcard
  # forms, so concrete entries, resource wildcards, and `*` all appear.
  defp granted_generator do
    grantable =
      @catalog_scopes ++
        ["*", "documents.*", "webhooks.*", "trackers.*", "documents.read.*"]

    list_of(member_of(grantable), max_length: 6)
  end

  # A concrete `<resource>.<action>` scope guaranteed to be absent from the
  # catalog (its resource is never `documents`/`webhooks`).
  defp uncatalogued_scope_generator do
    gen all(
          resource <- member_of(~w(trackers billing accounts unknownres)),
          action <- member_of(~w(read write admin list delete))
        ) do
      "#{resource}.#{action}"
    end
  end

  defp replace_at(string, pos, replacement) do
    {head, tail} = String.split_at(string, pos)
    <<_::utf8, rest::binary>> = tail
    head <> replacement <> rest
  end

  defp flip_byte(binary, pos, xor) do
    # `pos` is bound outside this match, so Elixir 1.20 requires it be
    # pinned where it sizes the bitstring segment.
    <<head::binary-size(^pos), byte, rest::binary>> = binary
    <<head::binary, Bitwise.bxor(byte, xor), rest::binary>>
  end
end
