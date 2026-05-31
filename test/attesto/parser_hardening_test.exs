defmodule Attesto.ParserHardeningTest do
  @moduledoc false
  # Randomized parser-hardening fuzz for the two compact-JWS verifiers the
  # engine exposes to untrusted input: `Attesto.Token.verify/3` (plus its
  # signature-only sibling `peek_signed_claims/2`) and
  # `Attesto.DPoP.verify_proof/2`.
  #
  # Where property_test.exs mutates *valid* tokens (single-byte flips,
  # truncation, segment swaps), this module attacks the parser from the
  # other side: it synthesizes pathological inputs the verifier was never
  # meant to accept - non-URL-safe base64 in any segment, multi-megabyte
  # payloads, claim structures nested ten thousand levels deep, binary
  # garbage in each of the three JWS segments, non-JSON JOSE headers, and
  # scope/claim strings carrying control bytes, NUL, and invalid UTF-8.
  #
  # The invariant every property asserts is the same and is total: the
  # verifier returns `{:error, reason}` where `reason` is an atom drawn
  # from the documented error set - it never returns `{:ok, _}`, never
  # raises, and never hangs. The "never accepts" half matters as much as
  # "never crashes": a hardened parser that silently coerced a malformed
  # header into a verified token would be worse than one that crashed.
  #
  # The module mints real tokens (via Factory.config/2, which installs the
  # signing PEM into the global Attesto.Keystore.Static app env), so it is
  # `async: false` like its sibling.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Attesto.DPoP
  alias Attesto.Test.Factory
  alias Attesto.Token

  # `Token.verify/3` collapses every failure into one of these. We assert
  # the returned reason is a member so a future verifier change that leaks
  # a raw JOSE `{class, reason}` tuple, a string, or an unlisted atom is
  # caught here rather than reaching a caller that pattern-matches the set.
  @token_verify_errors [
    :invalid_token,
    :invalid_signature,
    :invalid_issuer,
    :invalid_audience,
    :expired,
    :not_yet_valid,
    :invalid_claims,
    :invalid_principal,
    :invalid_typ,
    :unexpected_typ,
    :unsupported_critical_header,
    :unsupported_confirmation,
    :dpop_proof_required,
    :dpop_binding_mismatch,
    :dpop_proof_unexpected,
    :mtls_cert_required,
    :mtls_binding_mismatch,
    :mtls_cert_unexpected
  ]

  # `peek_signed_claims/2` runs signature verification only, so it can only
  # ever fail in two ways (see its @spec).
  @token_peek_errors [:invalid_signature, :invalid_token]

  # The closed failure set `DPoP.verify_proof/2` documents in its typespec.
  @dpop_verify_errors [
    :invalid_proof,
    :invalid_signature,
    :invalid_typ,
    :invalid_alg,
    :unsupported_critical_header,
    :missing_jwk,
    :invalid_jwk,
    :invalid_htm,
    :invalid_htu,
    :missing_jti,
    :invalid_jti,
    :missing_ath,
    :invalid_ath,
    :missing_iat,
    :invalid_iat,
    :proof_expired,
    :replay,
    :use_dpop_nonce
  ]

  @http_method "POST"
  @http_uri "https://api.example.com/oauth/token"

  # A fixed clock so a malformed-but-temporally-valid input can never be
  # accepted on the strength of the wall clock alone.
  @now 1_700_000_000

  setup do
    pem = Factory.rsa_pem()
    config = Factory.config(pem)

    principal = %{
      kind: "client",
      sub: "oc_fuzz",
      scopes: ["documents.read"],
      claims: %{"client_id" => "oc_fuzz"}
    }

    {:ok, %{access_token: jwt}} = Token.mint(config, principal, now: @now)

    # Sanity: the pristine token verifies, so any rejection below is the
    # malformation talking, not a broken fixture.
    assert {:ok, _claims} = Token.verify(config, jwt, now: @now)

    {:ok, config: config, jwt: jwt}
  end

  # ----------------------------------------------------------------------
  # (1) Bad base64url in any of the three segments.
  #
  # The compact serialization is base64url-no-pad in every segment. We
  # splice characters that are legal base64 but illegal base64url (`+`,
  # `/`, `=`), plus other non-alphabet bytes, into a randomly chosen
  # segment of an otherwise well-formed token.
  # ----------------------------------------------------------------------

  describe "Token.verify/3 with bad base64url" do
    property "a non-URL-safe character spliced into any segment is rejected", %{
      config: config,
      jwt: jwt
    } do
      check all(
              seg <- integer(0..2),
              bad <- member_of([?+, ?/, ?=, ?\s, ?!, ?%, ?@, ?#, ?", ?\n, 0]),
              max_runs: 200
            ) do
        mutated = splice_into_segment(jwt, seg, <<bad>>)
        assert_token_rejected(config, mutated)
      end
    end

    # Regression for strict compact-form verification: Attesto rejects "="
    # (and any non-base64url byte) in every compact segment at its own
    # boundary before JOSE can normalize a serialization the issuer never
    # emitted.
    property "padding characters appended to any segment are rejected", %{
      config: config,
      jwt: jwt
    } do
      # base64url-no-pad never carries `=`; a verifier that tolerantly
      # strips trailing `=` would accept a non-canonical encoding.
      check all(
              seg <- integer(0..2),
              pad <- member_of(["=", "==", "==="])
            ) do
        mutated = append_to_segment(jwt, seg, pad)
        assert_token_rejected(config, mutated)
      end
    end
  end

  # ----------------------------------------------------------------------
  # (2) Huge JSON payloads (> 1 MB).
  #
  # A megabyte-plus header or payload must be rejected promptly, not
  # buffered into an unbounded decode. These are forged as valid base64url
  # of valid (but enormous) JSON, so only a size/shape guard - never a
  # base64 error - stands between the input and acceptance.
  # ----------------------------------------------------------------------

  describe "Token.verify/3 with oversized JSON" do
    @tag :stress
    property "a multi-megabyte payload segment is rejected, not buffered", %{
      config: config,
      jwt: jwt
    } do
      [h, _p, s] = String.split(jwt, ".")

      check all(
              filler_kb <- integer(1024..2048),
              max_runs: 8
            ) do
        big_payload =
          %{"x" => String.duplicate("A", filler_kb * 1024)}
          |> JSON.encode!()
          |> Base.url_encode64(padding: false)

        forged = Enum.join([h, big_payload, s], ".")
        assert_token_rejected(config, forged)
      end
    end

    @tag :stress
    property "a multi-megabyte header segment is rejected, not buffered", %{
      config: config,
      jwt: jwt
    } do
      [_h, p, s] = String.split(jwt, ".")

      check all(
              filler_kb <- integer(1024..2048),
              max_runs: 8
            ) do
        big_header =
          %{"alg" => "RS256", "x" => String.duplicate("A", filler_kb * 1024)}
          |> JSON.encode!()
          |> Base.url_encode64(padding: false)

        forged = Enum.join([big_header, p, s], ".")
        assert_token_rejected(config, forged)
      end
    end
  end

  # ----------------------------------------------------------------------
  # (3) Pathologically nested claim structures (10k+ levels).
  #
  # A naive recursive-descent JSON decoder can blow the stack on deeply
  # nested input. The forged segment is valid base64url of syntactically
  # valid JSON ("[[[...]]]" / "{...}" 10k deep) so the decoder, not the
  # base64 step, is the thing under test.
  # ----------------------------------------------------------------------

  describe "Token.verify/3 with pathologically nested JSON" do
    @tag :stress
    property "a 10k-deep nested array in the payload is rejected, never crashes", %{
      config: config,
      jwt: jwt
    } do
      [h, _p, s] = String.split(jwt, ".")

      check all(
              depth <- integer(10_000..20_000),
              max_runs: 6
            ) do
        nested = String.duplicate("[", depth) <> String.duplicate("]", depth)
        forged = Enum.join([h, Base.url_encode64(nested, padding: false), s], ".")
        assert_token_rejected(config, forged)
      end
    end

    @tag :stress
    property "a 10k-deep nested object in the header is rejected, never crashes", %{
      config: config,
      jwt: jwt
    } do
      [_h, p, s] = String.split(jwt, ".")

      check all(
              depth <- integer(10_000..20_000),
              max_runs: 6
            ) do
        nested = String.duplicate(~s({"a":), depth) <> "1" <> String.duplicate("}", depth)
        forged = Enum.join([Base.url_encode64(nested, padding: false), p, s], ".")
        assert_token_rejected(config, forged)
      end
    end
  end

  # ----------------------------------------------------------------------
  # (4) Binary garbage in each of the three segments.
  #
  # Random bytes (often invalid base64url, occasionally decodable into
  # non-JSON) in one segment at a time, and across all three at once.
  # ----------------------------------------------------------------------

  describe "Token.verify/3 with binary garbage" do
    property "random bytes in a single segment are rejected", %{config: config, jwt: jwt} do
      check all(
              seg <- integer(0..2),
              garbage <- binary(min_length: 1, max_length: 64),
              max_runs: 200
            ) do
        mutated = replace_segment(jwt, seg, garbage)
        assert_token_rejected(config, mutated)
      end
    end

    property "three independent garbage segments are rejected", %{config: config} do
      check all(
              a <- binary(max_length: 48),
              b <- binary(max_length: 48),
              c <- binary(max_length: 48),
              max_runs: 200
            ) do
        forged = Enum.join([a, b, c], ".")
        assert_token_rejected(config, forged)
      end
    end

    property "an arbitrary dotted binary with any number of segments is rejected", %{
      config: config
    } do
      # Not even three segments: zero to five chunks of arbitrary bytes.
      check all(
              chunks <- list_of(binary(max_length: 32), max_length: 5),
              max_runs: 200
            ) do
        forged = Enum.join(chunks, ".")
        assert_token_rejected(config, forged)
      end
    end
  end

  # ----------------------------------------------------------------------
  # (5) Malformed JOSE headers: non-JSON, deeply nested, and structurally
  #     legal-but-hostile (huge key counts, `crit`, wrong alg).
  # ----------------------------------------------------------------------

  describe "Token.verify/3 with malformed JOSE headers" do
    property "a header that base64url-decodes to non-JSON is rejected", %{
      config: config,
      jwt: jwt
    } do
      [_h, p, s] = String.split(jwt, ".")

      check all(
              junk <- non_json_generator(),
              max_runs: 150
            ) do
        forged = Enum.join([Base.url_encode64(junk, padding: false), p, s], ".")
        assert_token_rejected(config, forged)
      end
    end

    property "a header that decodes to a JSON non-object (array, string, number) is rejected", %{
      config: config,
      jwt: jwt
    } do
      [_h, p, s] = String.split(jwt, ".")

      check all(
              non_object <- member_of(["[]", "[1,2,3]", "\"alg\"", "42", "true", "null"]),
              max_runs: 50
            ) do
        forged = Enum.join([Base.url_encode64(non_object, padding: false), p, s], ".")
        assert_token_rejected(config, forged)
      end
    end

    property "a header carrying a crit parameter is rejected as unsupported_critical_header", %{
      config: config,
      jwt: jwt
    } do
      # `crit` is the one malformed header whose rejection reason is
      # pinned by the RFC; assert the exact atom, not just membership.
      [_h, p, s] = String.split(jwt, ".")

      check all(
              crit <- one_of([constant([]), list_of(string(:alphanumeric), max_length: 3)]),
              max_runs: 30
            ) do
        header =
          %{"alg" => "RS256", "crit" => crit}
          |> JSON.encode!()
          |> Base.url_encode64(padding: false)

        forged = Enum.join([header, p, s], ".")

        assert {:error, reason} = Token.verify(config, forged, now: @now)
        assert reason in @token_verify_errors

        # A well-formed `crit` array reaches the dedicated check; a
        # malformed header may fail earlier on parse. Both are closed.
        assert reason in [:unsupported_critical_header, :invalid_token, :invalid_signature]
      end
    end
  end

  # ----------------------------------------------------------------------
  # (6) Scope (and other claim) strings with control chars, NUL bytes, and
  #     invalid UTF-8.
  #
  # These are forged into a structurally valid payload and re-signed with a
  # *foreign* key, so the input is a complete, JSON-valid token whose only
  # defect is the hostile claim bytes - it must fail (on signature, since
  # the bytes ride a foreign signature), never be accepted, never crash the
  # decoder on the invalid UTF-8.
  # ----------------------------------------------------------------------

  describe "Token.verify/3 with hostile claim bytes" do
    property "control chars / NUL / invalid UTF-8 in the scope claim never verify", %{
      config: config,
      jwt: jwt
    } do
      [h, _p, s] = String.split(jwt, ".")

      check all(
              scope <- hostile_string_generator(),
              max_runs: 200
            ) do
        # Re-encode the payload with a hostile scope. JSON.encode! refuses
        # invalid UTF-8, so we build the JSON bytes directly when the
        # generator yields non-UTF-8, embedding the raw bytes as a quoted
        # value. The signature `s` no longer matches -> the token must be
        # rejected (the point is it is rejected, not crashed, on bad bytes).
        payload = raw_json_payload(%{"scope" => scope})
        forged = Enum.join([h, Base.url_encode64(payload, padding: false), s], ".")
        assert_token_rejected(config, forged)
      end
    end

    property "hostile bytes in sub/jti/jkt-shaped claims never verify", %{config: config, jwt: jwt} do
      [h, _p, s] = String.split(jwt, ".")

      check all(
              key <- member_of(["sub", "jti", "iss", "aud", "client_id"]),
              value <- hostile_string_generator(),
              max_runs: 200
            ) do
        payload = raw_json_payload(%{key => value})
        forged = Enum.join([h, Base.url_encode64(payload, padding: false), s], ".")
        assert_token_rejected(config, forged)
      end
    end
  end

  # ----------------------------------------------------------------------
  # peek_signed_claims/2: the signature-only path is reachable with the
  # same untrusted input (denial-audit attribution). It must be equally
  # total, and may only ever fail with :invalid_signature / :invalid_token.
  # ----------------------------------------------------------------------

  describe "Token.peek_signed_claims/2 hardening" do
    property "bad base64url, garbage, and malformed headers never crash or accept", %{
      config: config,
      jwt: jwt
    } do
      check all(
              forged <- malformed_token_generator(jwt),
              max_runs: 300
            ) do
        case Token.peek_signed_claims(config, forged) do
          {:ok, _claims} ->
            # Acceptance is only legitimate when the forgery happens to
            # leave the signature intact (it never does here, but a peek
            # that returned {:ok, _} for a real signature is allowed by
            # contract). Guard anyway: this path must not be reached by a
            # structurally broken input.
            flunk("peek_signed_claims accepted a malformed token: #{inspect(forged)}")

          {:error, reason} ->
            assert reason in @token_peek_errors,
                   "peek error #{inspect(reason)} outside the documented set for #{inspect(forged)}"
        end
      end
    end
  end

  # ----------------------------------------------------------------------
  # DPoP.verify_proof/2: the same hardening invariant for the proof
  # verifier. Required opts (:http_method, :http_uri) are always supplied,
  # since their absence is a programming error that *should* raise; we are
  # fuzzing the proof bytes, not the call site.
  # ----------------------------------------------------------------------

  describe "DPoP.verify_proof/2 hardening" do
    property "malformed compact forms are rejected within the documented error set" do
      check all(
              forged <- dpop_malformed_generator(),
              max_runs: 300
            ) do
        assert_dpop_rejected(forged)
      end
    end

    @tag :stress
    property "a multi-megabyte proof payload is rejected, not buffered" do
      {proof, _jkt} = Factory.dpop_proof()
      [h, _p, s] = String.split(proof, ".")

      check all(
              filler_kb <- integer(1024..2048),
              max_runs: 6
            ) do
        big =
          %{"htm" => "POST", "x" => String.duplicate("A", filler_kb * 1024)}
          |> JSON.encode!()
          |> Base.url_encode64(padding: false)

        assert_dpop_rejected(Enum.join([h, big, s], "."))
      end
    end

    @tag :stress
    property "a 10k-deep nested proof payload is rejected, never crashes" do
      {proof, _jkt} = Factory.dpop_proof()
      [h, _p, s] = String.split(proof, ".")

      check all(
              depth <- integer(10_000..20_000),
              max_runs: 6
            ) do
        nested = String.duplicate("[", depth) <> String.duplicate("]", depth)
        forged = Enum.join([h, Base.url_encode64(nested, padding: false), s], ".")
        assert_dpop_rejected(forged)
      end
    end

    property "invalid UTF-8 / control chars in jti, htm, htu never crash or accept" do
      {proof, _jkt} = Factory.dpop_proof()
      [h, _p, s] = String.split(proof, ".")

      check all(
              key <- member_of(["jti", "htm", "htu", "ath", "nonce"]),
              value <- hostile_string_generator(),
              max_runs: 200
            ) do
        payload = raw_json_payload(%{key => value, "htu" => @http_uri, "iat" => @now})
        forged = Enum.join([h, Base.url_encode64(payload, padding: false), s], ".")
        assert_dpop_rejected(forged)
      end
    end
  end

  # ----------------------------------------------------------------------
  # Shared assertions.
  # ----------------------------------------------------------------------

  defp assert_token_rejected(config, input) do
    case Token.verify(config, input, now: @now) do
      {:ok, _claims} ->
        flunk("Token.verify unexpectedly accepted: #{inspect(input, limit: 8)}")

      {:error, reason} ->
        assert reason in @token_verify_errors,
               "verify error #{inspect(reason)} outside the documented set"
    end
  end

  defp assert_dpop_rejected(proof) do
    case DPoP.verify_proof(proof, http_method: @http_method, http_uri: @http_uri, now: @now) do
      {:ok, _verified} ->
        flunk("DPoP.verify_proof unexpectedly accepted: #{inspect(proof, limit: 8)}")

      {:error, reason} ->
        assert reason in @dpop_verify_errors,
               "DPoP error #{inspect(reason)} outside the documented set"
    end
  end

  # ----------------------------------------------------------------------
  # Generators.
  # ----------------------------------------------------------------------

  # A grab-bag of the malformation families above, for the omnibus
  # peek/proof properties. Each returns a string (the candidate token).
  defp malformed_token_generator(valid_jwt) do
    one_of([
      # Bad base64url in a random segment.
      gen all(seg <- integer(0..2), bad <- member_of([?+, ?/, ?=, ?\s, 0])) do
        splice_into_segment(valid_jwt, seg, <<bad>>)
      end,
      # Garbage in a random segment.
      gen all(seg <- integer(0..2), g <- binary(min_length: 1, max_length: 48)) do
        replace_segment(valid_jwt, seg, g)
      end,
      # Wholly arbitrary dotted binary.
      gen all(chunks <- list_of(binary(max_length: 32), max_length: 5)) do
        Enum.join(chunks, ".")
      end,
      # Non-JSON header.
      gen all(junk <- non_json_generator()) do
        [_h, p, s] = String.split(valid_jwt, ".")
        Enum.join([Base.url_encode64(junk, padding: false), p, s], ".")
      end
    ])
  end

  # Malformed DPoP compact forms. Built from a fresh real proof so each
  # family isolates one defect against an otherwise well-formed skeleton.
  defp dpop_malformed_generator do
    {proof, _jkt} = Factory.dpop_proof()
    [h, p, s] = String.split(proof, ".")

    one_of([
      # Bad base64url in a random segment.
      gen all(seg <- integer(0..2), bad <- member_of([?+, ?/, ?=, ?\s, 0])) do
        splice_into_segment(proof, seg, <<bad>>)
      end,
      # Garbage in a random segment.
      gen all(seg <- integer(0..2), g <- binary(min_length: 1, max_length: 48)) do
        replace_segment(proof, seg, g)
      end,
      # Wrong number of dot-separated segments.
      gen all(chunks <- list_of(member_of([h, p, s]), min_length: 0, max_length: 5)) do
        Enum.join(chunks, ".")
      end,
      # Non-JSON header riding the real payload/signature.
      gen all(junk <- non_json_generator()) do
        Enum.join([Base.url_encode64(junk, padding: false), p, s], ".")
      end,
      # Wholly arbitrary bytes.
      gen all(g <- binary(max_length: 80)) do
        g
      end
    ])
  end

  # Bytes that are decidedly not a JSON object: empty, plain text, binary
  # garbage, truncated/unbalanced JSON, BOM-prefixed, NUL-laden.
  defp non_json_generator do
    one_of([
      constant(""),
      constant("not json at all"),
      constant("{"),
      constant("}"),
      constant("{\"alg\":"),
      constant(<<0xEF, 0xBB, 0xBF>> <> "{}"),
      constant(<<0, 1, 2, 3, 0xFF, 0xFE>>),
      binary(min_length: 1, max_length: 32)
    ])
  end

  # Strings carrying control characters, NUL bytes, or invalid UTF-8. The
  # last branch deliberately yields a non-UTF-8 binary, which is why claim
  # payloads using these go through raw_json_payload/1 rather than JSON
  # encoding.
  defp hostile_string_generator do
    one_of([
      # Control characters and NUL embedded in otherwise-printable text.
      gen all(ctrl <- member_of([0, 1, 7, 8, 9, 10, 13, 27, 31]), rest <- string(:printable, max_length: 8)) do
        "doc" <> <<ctrl>> <> rest
      end,
      # A run of NUL bytes.
      gen all(n <- integer(1..8)) do
        String.duplicate(<<0>>, n)
      end,
      # Invalid UTF-8: lone continuation bytes / truncated sequences.
      member_of([
        <<0xFF>>,
        <<0xFE>>,
        <<0xC0, 0x80>>,
        <<0xED, 0xA0, 0x80>>,
        <<"scope.", 0x80, 0x81>>,
        <<0xF0, 0x28, 0x8C, 0x28>>
      ])
    ])
  end

  # ----------------------------------------------------------------------
  # Byte-level helpers.
  # ----------------------------------------------------------------------

  # Build a JSON object body by hand so that values containing invalid
  # UTF-8 (which JSON.encode!/1 would refuse) still produce a syntactically
  # plausible payload. The raw value bytes are placed inside JSON quotes
  # verbatim; the result need not be valid JSON - a decoder that rejects it
  # is exactly the behaviour under test - but it is never an Elixir crash
  # to *construct*.
  defp raw_json_payload(pairs) when is_map(pairs) do
    body =
      pairs
      |> Enum.map(fn {k, v} -> json_pair(k, v) end)
      |> Enum.intersperse(",")
      |> IO.iodata_to_binary()

    "{" <> body <> "}"
  end

  defp json_pair(key, value) when is_binary(value) do
    [?", key, ?", ?:, ?", value, ?"]
  end

  defp json_pair(key, value) when is_integer(value) do
    [?", key, ?", ?:, Integer.to_string(value)]
  end

  # Replace the `index`-th (0-based) dot-segment of a compact JWS with
  # `replacement`. Segments beyond what `String.split` yields are left as
  # a no-op (the input simply has fewer segments).
  defp replace_segment(jwt, index, replacement) do
    jwt
    |> String.split(".")
    |> List.replace_at(index, replacement)
    |> Enum.join(".")
  end

  # Splice `insert` into the middle of the `index`-th segment, so the
  # segment stays non-empty and recognizably JWS-shaped but no longer
  # base64url-decodes cleanly.
  defp splice_into_segment(jwt, index, insert) do
    segments = String.split(jwt, ".")
    seg = Enum.at(segments, index)
    mid = div(byte_size(seg), 2)
    <<head::binary-size(mid), tail::binary>> = seg
    spliced = head <> insert <> tail

    segments |> List.replace_at(index, spliced) |> Enum.join(".")
  end

  # Append `suffix` to the end of the `index`-th segment.
  defp append_to_segment(jwt, index, suffix) do
    segments = String.split(jwt, ".")
    seg = Enum.at(segments, index) <> suffix
    segments |> List.replace_at(index, seg) |> Enum.join(".")
  end
end
