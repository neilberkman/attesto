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
  alias Attesto.Secret
  alias Attesto.Test.Factory
  alias Attesto.Thumbprint
  alias Attesto.Token

  @thumbprint_length 43
  @base64url_no_pad ~r/\A[A-Za-z0-9_-]{43}\z/

  # base64url-no-pad alphabet of any length: the exact shape Secret.generate/1
  # emits (no `=` padding, no `+`/`/` from standard base64).
  @base64url_no_pad_any ~r/\A[A-Za-z0-9_-]+\z/

  # RFC 7636 §4.1 unreserved verifier alphabet.
  @verifier_chars Enum.concat([?A..?Z, ?a..?z, ?0..?9, [?-, ?., ?_, ?~]])

  # A small, fixed scope catalog with two resources so resource-level
  # wildcards have something to match and miss.
  @catalog_scopes ~w(
    documents.read documents.write
    webhooks.read webhooks.write webhooks.admin
  )

  # The distinct resources of @catalog_scopes, used to drive the resource-level
  # wildcard safety property.
  @catalog_resources ~w(documents webhooks)

  # A representative set of characters OUTSIDE the RFC 7636 §4.1 unreserved
  # alphabet `[A-Za-z0-9-._~]`, used to mutate a valid verifier into an
  # alphabet-invalid one. Spans the standard-base64 specials, padding, space,
  # and a few reserved/control bytes.
  @non_unreserved_chars [?/, ?+, ?=, ?\s, ?%, ?!, ?:, ?@, ?#, ?&, ?*, 0x00, 0x7F]

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
  # (1b) Attesto.Secret: generated secrets are base64url-no-pad, unique, and
  #      hash/1 is a deterministic Thumbprint.of/1.
  # ----------------------------------------------------------------------

  describe "Secret.generate/1" do
    property "with N bytes of entropy always yields a base64url-no-pad string" do
      # Across the whole supported entropy range a generated secret is a
      # non-empty string drawn only from the base64url alphabet, with no `=`
      # padding and none of standard base64's `+`/`/` (Base.url_encode64
      # padding: false, secret.ex line 33).
      check all(bytes <- integer(1..256)) do
        secret = Secret.generate(bytes)

        assert is_binary(secret)
        assert Regex.match?(@base64url_no_pad_any, secret)
        refute String.contains?(secret, "=")
        refute String.contains?(secret, "+")
        refute String.contains?(secret, "/")
      end
    end

    property "the encoded length is the base64url-no-pad length of N bytes" do
      # base64url-no-pad encodes 3 bytes to 4 chars; the no-pad tail of a
      # partial group is ceil(bytes * 8 / 6) characters. This pins that the
      # generator emits exactly `bytes` bytes of entropy, no more.
      check all(bytes <- integer(1..256)) do
        expected = div(bytes * 8 + 5, 6)
        assert String.length(Secret.generate(bytes)) == expected
      end
    end

    property "distinct calls produce distinct secrets (cryptographic randomness)" do
      # A property-based form of secret_test.exs lines 34-37: a batch of
      # default-entropy secrets are all distinct. 256 bits of entropy makes a
      # collision astronomically unlikely, so any repeat signals a broken
      # generator rather than bad luck.
      check all(count <- integer(2..200)) do
        secrets = for _ <- 1..count, do: Secret.generate()
        assert length(Enum.uniq(secrets)) == count
      end
    end
  end

  describe "Secret.hash/1" do
    property "is deterministic and equals Thumbprint.of/1 for any input" do
      # hash/1 is the storage-key function; it must be a pure, deterministic
      # SHA-256 thumbprint of its input so a presented secret always hashes
      # to the same lookup key (secret.ex line 40 delegates to Thumbprint.of).
      check all(input <- binary()) do
        assert Secret.hash(input) == Secret.hash(input)
        assert Secret.hash(input) == Thumbprint.of(input)
      end
    end

    property "of any generated secret is a canonical 43-char thumbprint" do
      check all(bytes <- integer(1..256)) do
        hash = Secret.hash(Secret.generate(bytes))

        assert String.length(hash) == @thumbprint_length
        assert Regex.match?(@base64url_no_pad, hash)
        assert Thumbprint.valid?(hash)
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
  # (3b) PKCE mutation tolerance: a valid verifier flipped to a non-unreserved
  #      character is rejected, and a malformed challenge never verifies.
  # ----------------------------------------------------------------------

  describe "PKCE.verify mutation tolerance" do
    property "a single byte of a valid verifier mutated to a non-unreserved char fails" do
      # Take a well-formed verifier, overwrite one position with a character
      # outside `[A-Za-z0-9-._~]`. The result keeps a legal length but breaks
      # the alphabet, so verify/3 must short-circuit to :invalid_verifier
      # (alphabet is checked before the challenge compare, pkce.ex line 94).
      check all(
              verifier <- verifier_generator(),
              bad <- member_of(@non_unreserved_chars),
              pos <- integer(0..(String.length(verifier) - 1))
            ) do
        {:ok, challenge} = PKCE.challenge(verifier)
        mutated = replace_at(verifier, pos, <<bad>>)

        # The mutation genuinely changed the verifier and broke its alphabet.
        refute PKCE.valid_verifier?(mutated)
        assert PKCE.verify(challenge, mutated) == {:error, :invalid_verifier}
      end
    end

    property "a corrupt (non-canonical) challenge never verifies against its verifier" do
      # A stored challenge that is not a canonical 43-char base64url SHA-256
      # value could never have been produced by challenge/1. Even presented
      # with the *correct* verifier, verify/3 must report :invalid_challenge
      # (pkce.ex line 95), never :ok - a corrupt store is a hard failure, not
      # a coincidental match.
      check all(
              verifier <- verifier_generator(),
              challenge <- malformed_challenge_generator()
            ) do
        refute PKCE.valid_challenge?(challenge)
        assert PKCE.verify(challenge, verifier) == {:error, :invalid_challenge}
      end
    end

    property "any challenge method other than S256 is unsupported, whatever the inputs" do
      # The plain-method downgrade and every other method string is rejected
      # before any verifier/challenge inspection (pkce.ex line 101), so a
      # downgrade can never succeed even with a matching verifier+challenge.
      check all(
              verifier <- verifier_generator(),
              method <- non_s256_method_generator()
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

    property "a resource-level wildcard covers ONLY its own resource (no cross-resource leak)" do
      # `R.*` grants every catalog action under resource R and nothing under
      # any other resource. Over every catalog entry, grants?(cat, ["R.*"], e)
      # is true IFF e's resource is R - so a wildcard for `documents` never
      # silently authorizes a `webhooks.*` scope and vice versa.
      check all(
              wildcard_resource <- member_of(@catalog_resources),
              required <- member_of(@catalog_scopes)
            ) do
        catalog = Scope.new_catalog(@catalog_scopes)
        granted = ["#{wildcard_resource}.*"]
        required_resource = required |> String.split(".", parts: 2) |> hd()

        assert Scope.grants?(catalog, granted, required) ==
                 (required_resource == wildcard_resource)
      end
    end

    property "narrowing is monotonic: a subset grant never authorizes more than its superset" do
      # If G1 ⊆ G2 then for every required scope R, grants?(cat, G1, R) implies
      # grants?(cat, G2, R). Adding grants can only ever expand authorization,
      # never revoke it - there is no grant that, once joined with another,
      # withdraws a previously-covered scope.
      check all(
              g1 <- granted_generator(),
              extra <- granted_generator(),
              required <- member_of(@catalog_scopes)
            ) do
        catalog = Scope.new_catalog(@catalog_scopes)
        # g1 is a literal sublist of g2 (g2 = g1 ++ extra), so g1 ⊆ g2.
        g2 = g1 ++ extra

        if Scope.grants?(catalog, g1, required) do
          assert Scope.grants?(catalog, g2, required)
        end
      end
    end
  end

  # ----------------------------------------------------------------------
  # (4b) Scope.valid_token?/1: the RFC 6749 NQCHAR alphabet, tested by
  #      exhausting the byte space rather than the fixed boundaries in
  #      scope_token_test.exs.
  # ----------------------------------------------------------------------

  describe "Scope.valid_token?/1 properties" do
    property "a single byte is a valid token IFF it is an NQCHAR" do
      # NQCHAR = %x21 / %x23-5B / %x5D-7E (printable ASCII minus space, `\"`,
      # `\\`). Walking every byte 0..255 pins the regex boundaries from both
      # sides: control bytes (<0x21), the three excluded printables, and every
      # high byte (>=0x80) are rejected; everything else is accepted.
      check all(byte <- integer(0..255)) do
        token = <<byte>>
        assert Scope.valid_token?(token) == nqchar_byte?(byte)
      end
    end

    property "a token is valid IFF all of its bytes are NQCHARs" do
      # The whole-string predicate is exactly the conjunction over its bytes:
      # any single non-NQCHAR byte anywhere in an otherwise-legal token (an
      # embedded space, quote, backslash, control char, or high byte) rejects
      # the entire token, since a stray space would split one grant into two
      # on the space-delimited wire.
      check all(bytes <- list_of(integer(0..255), min_length: 1, max_length: 12)) do
        token = :binary.list_to_bin(bytes)
        expected = Enum.all?(bytes, &nqchar_byte?/1)

        assert Scope.valid_token?(token) == expected
      end
    end

    property "the empty string is never a valid token (ABNF requires 1*NQCHAR)" do
      # A degenerate but load-bearing edge: valid_token?/1 must reject "" so an
      # empty grant can never masquerade as a token. Phrased as a property so
      # it lives beside the byte-range checks.
      check all(_ <- constant(nil)) do
        refute Scope.valid_token?("")
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

  # A canonical-length (43-char) but non-thumbprint challenge: right shape,
  # wrong alphabet, so valid_challenge?/1 (Thumbprint.valid?/1) rejects it.
  # Splicing a non-base64url byte into an otherwise valid challenge keeps the
  # length at 43 so only the alphabet check can fail it.
  defp malformed_challenge_generator do
    gen all(
          seed <- binary(),
          bad <- member_of([?!, ?+, ?/, ?=, ?\s, ?@, ?:]),
          pos <- integer(0..(@thumbprint_length - 1))
        ) do
      Thumbprint.of(seed)
      |> replace_at(pos, <<bad>>)
    end
  end

  # Any challenge method that is not exactly "S256", including the deliberately
  # unsupported "plain" downgrade and case/whitespace variants of S256.
  defp non_s256_method_generator do
    member_of(["plain", "PLAIN", "s256", "S256 ", " S256", "S384", "S512", "", "none", "RS256"])
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

  # RFC 6749 Appendix A NQCHAR = %x21 / %x23-5B / %x5D-7E: printable ASCII
  # excluding space (0x20), double-quote (0x22), and backslash (0x5C).
  defp nqchar_byte?(byte) do
    byte == 0x21 or byte in 0x23..0x5B or byte in 0x5D..0x7E
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
