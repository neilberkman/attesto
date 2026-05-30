defmodule Attesto.KeyFormatTest do
  @moduledoc false
  # PEM-format corners for Attesto.Key, benchmarked against the kinds of
  # key material a real deployment actually feeds it: not just the PKCS#1
  # `RSA PRIVATE KEY` the Factory mints, but a CRLF-line-ending PEM, a
  # PKCS#8 `PRIVATE KEY` (what `openssl genpkey` emits by default), an
  # EC P-256 private key, a public-only SPKI PEM, empty/garbage input, and
  # a multi-key PEM. (Compare thephpleague/oauth2-server's CryptKey tests,
  # which guard the same "what format did the operator hand us" surface.)
  #
  # Every assertion pins the CURRENT behavior. Cases where that behavior is
  # poor for a real deployment (an undocumented FunctionClauseError instead
  # of the documented ArgumentError; a kid/1 that silently returns `[]`
  # instead of raising) are flagged as source bugs in the returned report,
  # not papered over here.
  #
  # Pure functions over operator-provided PEM strings: no keystore, no
  # store, no app env. Safe to run concurrently.
  use ExUnit.Case, async: true

  alias Attesto.Key
  alias Attesto.Test.Factory

  # ----- PEM fixtures (built with :public_key so they are real keys) -----

  defp pkcs1_rsa_pem, do: Factory.rsa_pem(2048)

  # PKCS#8 (`-----BEGIN PRIVATE KEY-----`): the RSA key wrapped in a
  # PrivateKeyInfo, which is what `openssl genpkey -algorithm RSA` produces
  # by default and therefore the single most common operator-supplied
  # shape.
  defp pkcs8_rsa_pem do
    priv = :public_key.generate_key({:rsa, 2048, 65_537})
    :public_key.pem_encode([:public_key.pem_entry_encode(:PrivateKeyInfo, priv)])
  end

  # An EC P-256 (`prime256v1`/`secp256r1`) private key PEM. A deployment
  # that standardised on ES256 rather than RS256 would hand attesto exactly
  # this.
  defp ec_p256_private_pem do
    priv = :public_key.generate_key({:namedCurve, :secp256r1})
    :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, priv)])
  end

  # A public-only SPKI PEM (`-----BEGIN PUBLIC KEY-----`), as `public_pem/1`
  # itself emits and as a verification-only keystore entry would hold.
  defp rsa_public_only_pem, do: Key.public_pem(pkcs1_rsa_pem())

  # Two distinct RSA private keys concatenated into one PEM blob.
  defp multi_rsa_pem, do: pkcs1_rsa_pem() <> pkcs1_rsa_pem()

  defp pem_lines(pem), do: String.split(pem, "\n", trim: true)

  describe "PKCS#1 RSA PEM (the happy path, Factory.rsa_pem)" do
    setup do: {:ok, pem: pkcs1_rsa_pem()}

    test "public_pem/1 derives a conventional SPKI PUBLIC KEY PEM", %{pem: pem} do
      derived = Key.public_pem(pem)

      assert is_binary(derived)
      assert String.starts_with?(derived, "-----BEGIN PUBLIC KEY-----")
      assert String.contains?(derived, "-----END PUBLIC KEY-----")
      # normalize_pem/1 promises exactly one trailing newline.
      assert String.ends_with?(derived, "-----END PUBLIC KEY-----\n")
      refute String.ends_with?(derived, "\n\n")
    end

    test "the derived public PEM is itself parseable and yields the same kid", %{pem: pem} do
      derived = Key.public_pem(pem)
      # The whole point of deriving: the verification key always matches the
      # signing key, so both halves agree on the thumbprint.
      assert Key.kid(pem) == Key.kid(derived)
    end

    test "kid/1 is a stable RFC 7638 base64url thumbprint", %{pem: pem} do
      kid = Key.kid(pem)

      assert is_binary(kid)
      # 43-char base64url SHA-256 digest, no padding.
      assert String.length(kid) == 43
      assert kid =~ ~r/\A[A-Za-z0-9_-]+\z/
      # Deterministic for a given key.
      assert Key.kid(pem) == kid
    end

    test "jwk/1 parses to an RSA JOSE.JWK", %{pem: pem} do
      jwk = Key.jwk(pem)
      assert %JOSE.JWK{} = jwk
      # The public projection round-trips to a JWK map with kty RSA.
      {_, map} = JOSE.JWK.to_public_map(jwk)
      assert map["kty"] == "RSA"
    end
  end

  describe "CRLF line-ending PEM" do
    setup do
      pem = pkcs1_rsa_pem()
      %{lf: pem, crlf: String.replace(pem, "\n", "\r\n")}
    end

    test "public_pem/1 handles CRLF and derives the same public key as the LF PEM",
         %{lf: lf, crlf: crlf} do
      # `:public_key.pem_decode/1` tolerates CRLF, so a Windows-edited or
      # HTTP-transported key still works. Current behavior: equivalent to
      # the LF form.
      assert String.contains?(crlf, "\r\n")
      assert Key.public_pem(crlf) == Key.public_pem(lf)
    end

    test "kid/1 and jwk/1 are unaffected by CRLF", %{lf: lf, crlf: crlf} do
      assert Key.kid(crlf) == Key.kid(lf)
      assert %JOSE.JWK{} = Key.jwk(crlf)
    end
  end

  describe "PKCS#8 RSA PEM (openssl genpkey default)" do
    setup do: {:ok, pem: pkcs8_rsa_pem()}

    test "the fixture is genuinely PKCS#8 (PRIVATE KEY banner, not RSA PRIVATE KEY)",
         %{pem: pem} do
      assert String.contains?(pem, "-----BEGIN PRIVATE KEY-----")
      refute String.contains?(pem, "-----BEGIN RSA PRIVATE KEY-----")
    end

    test "public_pem/1 works: a PrivateKeyInfo decodes to an :RSAPrivateKey record",
         %{pem: pem} do
      # Current behavior: `:public_key.pem_entry_decode/1` unwraps the
      # PrivateKeyInfo to the same `:RSAPrivateKey` record the PKCS#1 path
      # produces, so the public-derivation clause matches and the SPKI PEM
      # comes out. This is the GOOD outcome - openssl's default format is
      # supported.
      derived = Key.public_pem(pem)
      assert String.starts_with?(derived, "-----BEGIN PUBLIC KEY-----")
    end

    test "kid/1 and jwk/1 work on a PKCS#8 RSA key", %{pem: pem} do
      assert %JOSE.JWK{} = Key.jwk(pem)
      assert String.length(Key.kid(pem)) == 43
    end
  end

  describe "EC P-256 private PEM" do
    setup do: {:ok, pem: ec_p256_private_pem()}

    test "public_pem/1 raises a clear ArgumentError on an EC key (attesto signs RS256)",
         %{pem: pem} do
      # An EC private key is structurally valid but not RSA. public_pem/1
      # fails with a clear ArgumentError naming the wrong key type, so an
      # ES256 misconfiguration is legible rather than an opaque crash.
      assert_raise ArgumentError, ~r/RSA private signing key/, fn -> Key.public_pem(pem) end
    end

    test "jwk/1 and kid/1 reject an EC key (attesto is RS256-only)", %{pem: pem} do
      # JOSE parses EC fine, but attesto signs and verifies RS256
      # exclusively, so an EC key has no valid role as a signing or
      # verification key. jwk/1 rejects it with a clear ArgumentError
      # naming the wrong key type - this is what stops an EC key from being
      # published in a JWKS mislabelled `alg: "RS256"`, or used as a signing
      # key that would crash deep inside JOSE at mint time. kid/1 goes
      # through jwk/1, so it rejects too.
      assert_raise ArgumentError, ~r/RSA key.*RS256.*EC/, fn -> Key.jwk(pem) end
      assert_raise ArgumentError, ~r/RSA key.*RS256.*EC/, fn -> Key.kid(pem) end
    end
  end

  describe "public-only PEM (no private half to derive from)" do
    setup do: {:ok, pem: rsa_public_only_pem()}

    test "public_pem/1 raises a clear ArgumentError on a public-only PEM", %{pem: pem} do
      # Re-deriving a public key from a public key is nonsensical; an
      # :RSAPublicKey record is not an RSA private signing key, so it now
      # fails with a clear ArgumentError rather than a FunctionClauseError.
      assert String.starts_with?(pem, "-----BEGIN PUBLIC KEY-----")
      assert_raise ArgumentError, ~r/RSA private signing key/, fn -> Key.public_pem(pem) end
    end

    test "kid/1 and jwk/1 work on a public-only PEM (this is the verification path)",
         %{pem: pem} do
      # A keystore's verification_pems may legitimately be public-only, and
      # kid/1 is computed over the public half, so this MUST work - and does.
      assert %JOSE.JWK{} = Key.jwk(pem)
      assert String.length(Key.kid(pem)) == 43
    end

    test "signing_jwk/1 rejects a public-only PEM before JOSE signing crashes", %{pem: pem} do
      assert_raise ArgumentError, ~r/RSA private signing key/, fn ->
        Key.signing_jwk(pem)
      end
    end

    test "the public-only PEM has the same kid as its source private key" do
      priv = pkcs1_rsa_pem()
      pub = Key.public_pem(priv)
      assert Key.kid(pub) == Key.kid(priv)
    end
  end

  describe "empty and garbage input" do
    test "public_pem/1 raises the DOCUMENTED ArgumentError on an empty string" do
      # This is the one path the moduledoc actually describes: no key entry
      # -> ArgumentError. Good behavior.
      assert_raise ArgumentError, ~r/no key entry/, fn -> Key.public_pem("") end
    end

    test "public_pem/1 raises ArgumentError on a non-PEM garbage string" do
      assert_raise ArgumentError, ~r/no key entry/, fn ->
        Key.public_pem("this is not a pem at all")
      end
    end

    test "jwk/1 raises ArgumentError on empty/garbage input" do
      # JOSE.JWK.from_pem/1 returns [] (not a %JOSE.JWK{}) for input with no
      # key entry; jwk/1 rejects that loudly instead of propagating a
      # non-struct that would poison kid/1 and key selection.
      assert_raise ArgumentError, ~r/exactly one parseable key/, fn -> Key.jwk("") end

      assert_raise ArgumentError, ~r/exactly one parseable key/, fn ->
        Key.jwk("this is not a pem at all")
      end
    end

    test "kid/1 raises ArgumentError on empty/garbage input" do
      # kid/1 delegates to jwk/1, so an empty/garbage verification PEM fails
      # loudly at load time rather than computing a non-string kid that would
      # silently poison candidate-key selection in Token.verify/3.
      assert_raise ArgumentError, ~r/exactly one parseable key/, fn -> Key.kid("") end

      assert_raise ArgumentError, ~r/exactly one parseable key/, fn ->
        Key.kid("this is not a pem at all")
      end
    end
  end

  describe "multi-key PEM (two RSA private keys concatenated)" do
    setup do: {:ok, pem: multi_rsa_pem()}

    test "the fixture really carries two key entries", %{pem: pem} do
      assert Enum.count(pem_lines(pem), &(&1 == "-----BEGIN RSA PRIVATE KEY-----")) == 2
    end

    test "public_pem/1 rejects a multi-key PEM rather than silently using the first", %{pem: pem} do
      # A PEM with more than one key entry is a misconfiguration (e.g. two
      # keys pasted during a rotation). public_pem/1 refuses it loudly
      # instead of silently deriving from the first key only.
      assert_raise ArgumentError, ~r/multiple key entries/, fn -> Key.public_pem(pem) end
    end

    test "kid/1 and jwk/1 raise ArgumentError on a multi-key PEM", %{pem: pem} do
      # JOSE.JWK.from_pem/1 returns a LIST for a multi-entry PEM; jwk/1
      # rejects a non-single-key result, so the whole module treats a
      # multi-key blob consistently (loud failure everywhere, not a silent
      # first-key derivation in one path and a crash in another).
      assert_raise ArgumentError, ~r/exactly one parseable key/, fn -> Key.kid(pem) end
      assert_raise ArgumentError, ~r/exactly one parseable key/, fn -> Key.jwk(pem) end
    end
  end
end
