defmodule Attesto.Key do
  @moduledoc """
  Pure helpers for working with the RSA signing material as PEM strings.

  An RSA private key already contains its public half, so there is never
  a separately stored public PEM to drift out of sync. `public_pem/1`
  derives the public key from a private PEM, giving exactly one source of
  truth: the verification key always matches the signing key. This closes
  a real failure mode where a tracked public PEM and a regenerated
  private key silently mismatch and every verification fails.

  `kid/1` is the RFC 7638 JWK thumbprint of a key's public half. It is
  stable for a given key and changes iff the key changes, so rotating to a
  new key yields a distinct `kid` automatically - no separate identifier
  to assign or track.
  """

  @doc """
  Derive the public key, in conventional SPKI
  (`-----BEGIN PUBLIC KEY-----`) PEM form, from a private RSA key PEM.

  Accepts the PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`) forms.
  Raises `ArgumentError` - signing material is operator-provided, so a
  misconfiguration is a deploy-time failure that should be loud rather
  than silently verifying against garbage - if `pem` contains no key
  entry, contains more than one, or contains a non-RSA key (attesto signs
  RS256; an EC or public-only key cannot be a signing key).
  """
  @spec public_pem(String.t()) :: String.t()
  def public_pem(pem) when is_binary(pem) do
    pem
    |> decode_rsa_private_key!()
    |> rsa_public_from_private()
    |> encode_spki_pem()
    |> normalize_pem()
  end

  @doc """
  The RFC 7638 SHA-256 JWK thumbprint (`kid`) of the public half of the
  key in `pem`. Accepts a private or public PEM; both yield the same
  thumbprint because it is computed over the public members only.
  """
  @spec kid(String.t()) :: String.t()
  def kid(pem) when is_binary(pem) do
    pem
    |> jwk()
    |> JOSE.JWK.thumbprint()
  end

  @doc """
  Parse a PEM (private or public) into a `JOSE.JWK`.

  Raises `ArgumentError` if `pem` does not contain exactly one parseable
  key. `JOSE.JWK.from_pem/1` returns `[]` for input with no key entry and
  a list for a multi-key PEM; left unguarded, `thumbprint/1` of those
  returns `[]` rather than a string, which would silently poison `kid/1`
  and verification-key selection. Failing loudly here surfaces a
  malformed keystore PEM as a configuration error instead of a
  request-time mystery.

  Also raises if the key is not RSA. Attesto signs and verifies RS256
  exclusively, so an EC (or any non-RSA) key has no valid role as a
  signing or verification key. Rejecting it here prevents two failure
  modes: a JWKS that advertises an EC key mislabelled `alg: "RS256"`
  (`Attesto.JWKS`), and an EC signing key that would otherwise crash deep
  inside JOSE at mint time instead of failing as a clear configuration
  error.
  """
  @spec jwk(String.t()) :: JOSE.JWK.t()
  def jwk(pem) when is_binary(pem) do
    case safe_from_pem(pem) do
      %JOSE.JWK{} = jwk ->
        ensure_rsa!(jwk)

      _other ->
        raise ArgumentError,
              "PEM did not contain exactly one parseable key (it was empty, " <>
                "malformed, or carried multiple key entries)"
    end
  end

  # Attesto is RS256-only: every signing and verification key must be RSA.
  # The `kty` is read from the JWK's own JSON map (RFC 7517), the same
  # canonical source `JOSE.JWK.to_public_map/1` and the thumbprint use.
  defp ensure_rsa!(%JOSE.JWK{} = jwk) do
    jwk
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> case do
      %{"kty" => "RSA"} ->
        jwk

      %{"kty" => kty} ->
        raise ArgumentError,
              "expected an RSA key (attesto signs and verifies RS256 only); got a " <>
                "#{inspect(kty)} key"
    end
  end

  # `JOSE.JWK.from_pem/1` returns `[]` for an empty/no-entry PEM and, for a
  # multi-entry PEM, raises a `FunctionClauseError` from deep inside JOSE
  # rather than returning a list. Normalise both into a single non-`JWK`
  # sentinel so `jwk/1` can fail with one clear `ArgumentError`.
  defp safe_from_pem(pem) do
    JOSE.JWK.from_pem(pem)
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  @doc """
  Parse a private PEM into a `JOSE.JWK` whose public half can sign and
  derive a `kid`.

  Unlike `jwk/1`, this rejects public-only RSA PEMs: they are valid
  verification material, but cannot sign RS256 tokens.
  """
  @spec signing_jwk(String.t()) :: JOSE.JWK.t()
  def signing_jwk(pem) when is_binary(pem) do
    pem
    |> decode_rsa_private_key!()
    |> rsa_public_from_private()

    jwk(pem)
  end

  # Decode the private key PEM to a key record. Accepts the PKCS#1
  # `RSA PRIVATE KEY` and the PKCS#8 `PRIVATE KEY` (PrivateKeyInfo, which
  # `pem_entry_decode/1` unwraps to an `:RSAPrivateKey`) forms. Rejects an
  # empty PEM and a multi-entry PEM loudly rather than silently using the
  # first key.
  defp decode_rsa_private_key!(pem) do
    case :public_key.pem_decode(pem) do
      [entry] ->
        :public_key.pem_entry_decode(entry)

      [] ->
        raise ArgumentError, "signing key PEM contained no key entry"

      [_ | _] ->
        raise ArgumentError,
              "signing key PEM contained multiple key entries; expected exactly one"
    end
  end

  # An RSA private key record carries the modulus and public exponent, so
  # the public key is recoverable with no separate material.
  defp rsa_public_from_private({:RSAPrivateKey, _ver, modulus, public_exponent, _d, _p, _q, _e1, _e2, _c, _other}) do
    {:RSAPublicKey, modulus, public_exponent}
  end

  # Attesto signs RS256, so the signing key must be RSA. A structurally
  # valid but non-RSA key (e.g. an EC private key, or a public-only PEM)
  # is a deploy-time misconfiguration: fail with a clear message rather
  # than an opaque FunctionClauseError.
  defp rsa_public_from_private(other) do
    raise ArgumentError,
          "expected an RSA private signing key (attesto signs RS256); got a " <>
            "#{inspect(elem(other, 0))} key"
  end

  defp encode_spki_pem(public_key) do
    :public_key.pem_encode([:public_key.pem_entry_encode(:SubjectPublicKeyInfo, public_key)])
  end

  # `:public_key.pem_encode/1` appends a trailing blank line after the
  # final `-----END ...-----` marker. Trim it so the derived PEM ends with
  # a single newline, matching the on-disk and env-var key shape.
  defp normalize_pem(pem) when is_binary(pem), do: String.trim_trailing(pem) <> "\n"
end
