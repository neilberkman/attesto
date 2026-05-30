defmodule Attesto.DPoPHtuTest do
  @moduledoc false
  # RFC 9449 §4.3 htu comparison edge cases.
  #
  # `Attesto.DPoP.check_htu/2` (via `normalize_htu/1`) does NOT implement a
  # normalizing URI verifier. It strips fragment and query from both the
  # proof's `htu` claim and the live `:http_uri`, then compares the two
  # remainders as raw strings with `==`. The only scheme handling is a
  # case-sensitive `String.starts_with?(uri, "https://")` gate on each side.
  #
  # The consequence is that attesto is STRICTER than a fully normalizing
  # RFC 3986 verifier on every dimension below (userinfo, default-port
  # equivalence, host case, percent-encoding, trailing slash): forms that
  # an RFC normalizer would treat as equivalent are rejected here because
  # the byte strings differ. Being stricter is a usability cost, not a
  # security gap: the verifier never accepts a request bound to a host or
  # path the client did not sign. There is no direction in which attesto is
  # MORE permissive than a normalizer about the host, so none of these edges
  # is flagged as a source bug.
  #
  # Each test asserts attesto's CURRENT behavior (the exact atom or :ok),
  # not the behavior a normalizer would have.
  use ExUnit.Case, async: true

  alias Attesto.DPoP
  alias Attesto.Test.Factory

  @http_method "POST"

  # Build verify opts. `:http_uri` is the server-observed (live) URI; the
  # proof's signed `htu` is supplied separately to Factory.dpop_proof.
  defp opts(http_uri, extra) do
    Keyword.merge([http_method: @http_method, http_uri: http_uri], extra)
  end

  # Sign a proof claiming `proof_htu` and verify it against a live request
  # observed at `live_uri`.
  defp verify(proof_htu, live_uri, extra \\ []) do
    {proof, _jkt} = Factory.dpop_proof(htu: proof_htu)
    DPoP.verify_proof(proof, opts(live_uri, extra))
  end

  # -----------------------------------------------------------------
  # baseline: identical strings verify
  # -----------------------------------------------------------------

  describe "exact-match baseline" do
    test "byte-identical htu and live uri verify" do
      uri = "https://api.example.com/resource"
      assert {:ok, result} = verify(uri, uri)
      assert result.htu == uri
    end
  end

  # -----------------------------------------------------------------
  # query and fragment stripping (the one normalization attesto does)
  # -----------------------------------------------------------------

  describe "query and fragment components" do
    # RFC 9449 §4.3: the client MUST construct htu WITHOUT query/fragment.
    # A proof whose own htu carries either is non-conformant and rejected;
    # the server-observed (live) URI may carry them and is normalized away.
    test "proof htu with a query is rejected" do
      assert {:error, :invalid_htu} =
               verify("https://api.example.com/resource?cb=1", "https://api.example.com/resource")
    end

    test "proof htu with a fragment is rejected" do
      assert {:error, :invalid_htu} =
               verify("https://api.example.com/resource#section", "https://api.example.com/resource")
    end

    test "proof htu with both query and fragment is rejected" do
      assert {:error, :invalid_htu} =
               verify("https://api.example.com/resource?cb=1&x=2#frag", "https://api.example.com/resource")
    end

    test "query/fragment on the live side are stripped (clean proof still matches)" do
      assert {:ok, _} =
               verify(
                 "https://api.example.com/resource",
                 "https://api.example.com/resource?cursor=abc#top"
               )
    end

    test "a clean proof matches regardless of the live side's query" do
      assert {:ok, _} =
               verify("https://api.example.com/resource", "https://api.example.com/resource?b=2")
    end

    test "a '?' embedded before the path divergence does not hide a path mismatch" do
      # Fragment split happens first, then query split. Here the paths
      # genuinely differ (/a vs /b) so it must reject.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a?x=1",
                 "https://api.example.com/b?x=1"
               )
    end
  end

  # -----------------------------------------------------------------
  # userinfo (https://user:pw@host/x)
  # -----------------------------------------------------------------

  describe "userinfo component" do
    test "userinfo in the proof htu is NOT stripped; mismatch vs userinfo-free live uri" do
      # An RFC 3986 normalizer drops userinfo before comparing authority;
      # attesto keeps it as part of the raw string, so the two differ.
      # Stricter than a normalizer, but safe (host still matches).
      assert {:error, :invalid_htu} =
               verify(
                 "https://user:pw@api.example.com/resource",
                 "https://api.example.com/resource"
               )
    end

    test "userinfo on both sides, byte-identical, verifies" do
      uri = "https://user:pw@api.example.com/resource"
      assert {:ok, _} = verify(uri, uri)
    end

    test "differing userinfo with same host is rejected (raw-string compare)" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://alice@api.example.com/resource",
                 "https://bob@api.example.com/resource"
               )
    end
  end

  # -----------------------------------------------------------------
  # default-port equivalence (host:443 vs host)
  # -----------------------------------------------------------------

  describe "default-port equivalence" do
    test "explicit :443 in proof htu does NOT match a port-less live uri" do
      # RFC 3986 §3.2.3: an explicit default port is equivalent to omitting
      # it. attesto compares raw strings, so :443 vs nothing differs.
      # Stricter than a normalizer, safe (same host).
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com:443/resource",
                 "https://api.example.com/resource"
               )
    end

    test "explicit :443 on both sides verifies" do
      uri = "https://api.example.com:443/resource"
      assert {:ok, _} = verify(uri, uri)
    end

    test "a genuinely different explicit port is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com:8443/resource",
                 "https://api.example.com/resource"
               )
    end
  end

  # -----------------------------------------------------------------
  # host / scheme case (HTTPS://HOST vs https://host)
  # -----------------------------------------------------------------

  describe "scheme and host case" do
    test "uppercase scheme in the proof htu fails the https:// gate" do
      # `String.starts_with?("HTTPS://...", "https://")` is false, so the
      # downgrade gate fires on the proof side and returns :invalid_htu
      # BEFORE any normalize/compare. RFC 3986 §3.1 makes scheme
      # case-insensitive; attesto's gate is case-sensitive.
      assert {:error, :invalid_htu} =
               verify(
                 "HTTPS://api.example.com/resource",
                 "https://api.example.com/resource"
               )
    end

    test "uppercase scheme in the live uri fails the https:// gate" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/resource",
                 "HTTPS://api.example.com/resource"
               )
    end

    test "lowercase https with differing HOST case is rejected (host not case-folded)" do
      # Scheme gate passes (both start with lowercase https://), then the
      # raw compare sees HOST != host. RFC 3986 §3.2.2 makes host
      # case-insensitive; attesto does not fold it. Stricter, and crucially
      # this is the SAFE direction: it never accepts a differently-cased
      # host as equal, it rejects it.
      assert {:error, :invalid_htu} =
               verify(
                 "https://API.EXAMPLE.COM/resource",
                 "https://api.example.com/resource"
               )
    end

    test "identical host casing on both sides verifies (even if uppercase)" do
      uri = "https://API.EXAMPLE.COM/resource"
      assert {:ok, _} = verify(uri, uri)
    end
  end

  # -----------------------------------------------------------------
  # IPv6 literal host
  # -----------------------------------------------------------------

  describe "IPv6 literal host" do
    test "identical bracketed IPv6 literals verify" do
      uri = "https://[2001:db8::1]/resource"
      assert {:ok, _} = verify(uri, uri)
    end

    test "IPv6 literal with explicit :443 does not match the port-less form" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://[2001:db8::1]:443/resource",
                 "https://[2001:db8::1]/resource"
               )
    end

    test "two textually different but numerically equal IPv6 literals are rejected" do
      # ::1 (compressed) vs 0:0:0:0:0:0:0:1 (expanded) are the same address
      # to an IP-aware comparator. attesto compares text, so they differ.
      assert {:error, :invalid_htu} =
               verify(
                 "https://[::1]/resource",
                 "https://[0:0:0:0:0:0:0:1]/resource"
               )
    end
  end

  # -----------------------------------------------------------------
  # path percent-encoding (%2F vs /)
  # -----------------------------------------------------------------

  describe "path percent-encoding" do
    test "%2F in the proof path does NOT match a literal '/' in the live path" do
      # %2F decodes to '/' but is NOT path-equivalent to a real segment
      # separator per RFC 3986 §2.2 (reserved). A decoding normalizer that
      # naively unescaped would conflate them; attesto compares raw and
      # keeps them distinct. Safe direction.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a%2Fb",
                 "https://api.example.com/a/b"
               )
    end

    test "identical percent-encoding on both sides verifies" do
      uri = "https://api.example.com/a%2Fb"
      assert {:ok, _} = verify(uri, uri)
    end

    test "case difference in a percent-encoding triple is rejected (%2f vs %2F)" do
      # RFC 3986 §6.2.2.1 normalizes percent-encoding hex to uppercase;
      # attesto does not, so %2f and %2F differ.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a%2fb",
                 "https://api.example.com/a%2Fb"
               )
    end

    test "an unencoded reserved char vs its percent form is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a b",
                 "https://api.example.com/a%20b"
               )
    end
  end

  # -----------------------------------------------------------------
  # trailing slash
  # -----------------------------------------------------------------

  describe "trailing slash" do
    test "trailing slash on the proof side only is rejected" do
      # RFC 3986 treats /resource and /resource/ as distinct paths anyway,
      # so this matches a normalizer: both reject. Asserted for completeness.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/resource/",
                 "https://api.example.com/resource"
               )
    end

    test "trailing slash on the live side only is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/resource",
                 "https://api.example.com/resource/"
               )
    end

    test "bare-authority trailing slash vs no path: '/' differs from empty" do
      # "https://host/" keeps the "/" after the split (no query/fragment),
      # while "https://host" has none. Distinct strings, rejected.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/",
                 "https://api.example.com"
               )
    end

    test "trailing slash present on both sides verifies" do
      uri = "https://api.example.com/resource/"
      assert {:ok, _} = verify(uri, uri)
    end
  end
end
