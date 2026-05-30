defmodule Attesto.PKCETest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.PKCE

  # RFC 7636 Appendix B worked example. These exact strings appear in the
  # spec, so matching them proves byte-level conformance with the S256
  # transform every other RFC 7636 implementation targets.
  @rfc_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @rfc_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  describe "challenge/1" do
    test "matches the RFC 7636 Appendix B S256 test vector" do
      assert {:ok, @rfc_challenge} = PKCE.challenge(@rfc_verifier)
    end

    test "produces a canonical 43-char base64url challenge" do
      verifier = String.duplicate("a", 50)
      assert {:ok, challenge} = PKCE.challenge(verifier)
      assert byte_size(challenge) == 43
      assert PKCE.valid_challenge?(challenge)
    end

    test "rejects a verifier shorter than 43 characters" do
      assert {:error, :invalid_verifier} = PKCE.challenge(String.duplicate("a", 42))
    end

    test "rejects a verifier longer than 128 characters" do
      assert {:error, :invalid_verifier} = PKCE.challenge(String.duplicate("a", 129))
    end

    test "rejects a verifier with characters outside the unreserved set" do
      # '+' and '/' are base64 but not in the PKCE unreserved alphabet.
      verifier = String.duplicate("a", 42) <> "+"
      assert {:error, :invalid_verifier} = PKCE.challenge(verifier)
    end
  end

  describe "verify/3" do
    test "accepts the matching verifier for a stored challenge (RFC vector)" do
      assert :ok = PKCE.verify(@rfc_challenge, @rfc_verifier)
    end

    test "accepts a round-tripped challenge/verifier pair" do
      verifier = "the-quick-brown-fox.jumps_over~the-lazy-dog0"
      assert {:ok, challenge} = PKCE.challenge(verifier)
      assert :ok = PKCE.verify(challenge, verifier)
    end

    test "rejects a non-matching but well-formed verifier as :mismatch" do
      other = String.duplicate("b", 50)
      assert {:error, :mismatch} = PKCE.verify(@rfc_challenge, other)
    end

    test "rejects the plain method (no downgrade)" do
      # Under 'plain', challenge == verifier and this would otherwise pass.
      assert {:error, :unsupported_method} =
               PKCE.verify(@rfc_verifier, @rfc_verifier, "plain")
    end

    test "rejects any non-S256 method" do
      assert {:error, :unsupported_method} = PKCE.verify(@rfc_challenge, @rfc_verifier, "S512")
      assert {:error, :unsupported_method} = PKCE.verify(@rfc_challenge, @rfc_verifier, "")
    end

    test "rejects a malformed verifier before comparing" do
      assert {:error, :invalid_verifier} = PKCE.verify(@rfc_challenge, "too-short")
    end

    test "rejects a corrupt stored challenge that could not be a real S256 output" do
      bad_challenge = String.duplicate("a", 20)
      assert {:error, :invalid_challenge} = PKCE.verify(bad_challenge, @rfc_verifier)
    end

    test "defaults the method to S256" do
      assert :ok = PKCE.verify(@rfc_challenge, @rfc_verifier)
    end
  end

  describe "valid_verifier?/1" do
    test "accepts 43 and 128 character boundaries" do
      assert PKCE.valid_verifier?(String.duplicate("a", 43))
      assert PKCE.valid_verifier?(String.duplicate("a", 128))
    end

    test "accepts the full unreserved alphabet" do
      assert PKCE.valid_verifier?("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop-._~0")
    end

    test "rejects out-of-range lengths and bad characters and non-binaries" do
      refute PKCE.valid_verifier?(String.duplicate("a", 42))
      refute PKCE.valid_verifier?(String.duplicate("a", 129))
      refute PKCE.valid_verifier?(String.duplicate("a", 43) <> " ")
      refute PKCE.valid_verifier?(:not_a_string)
    end
  end

  describe "valid_challenge?/1 and method/0" do
    test "valid_challenge? mirrors the canonical thumbprint shape" do
      assert {:ok, challenge} = PKCE.challenge(String.duplicate("z", 60))
      assert PKCE.valid_challenge?(challenge)
      refute PKCE.valid_challenge?("short")
      refute PKCE.valid_challenge?(String.duplicate("A", 43) <> "B")
    end

    test "method/0 is S256" do
      assert PKCE.method() == "S256"
    end
  end
end
