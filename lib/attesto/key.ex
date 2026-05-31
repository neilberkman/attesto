defmodule Attesto.Key do
  @moduledoc """
  Pure helpers for working with signing material as PEM strings.

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
  entry, contains more than one, contains a non-RSA key, or is
  public-only. EC/OKP deployments should publish JWKS instead.
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

  Also raises if the key type/curve is not supported by Attesto's
  asymmetric signing algorithms. Algorithms are derived from trusted key
  metadata, not from a presented token header.
  """
  @spec jwk(String.t()) :: JOSE.JWK.t()
  def jwk(pem) when is_binary(pem) do
    case safe_from_pem(pem) do
      %JOSE.JWK{} = jwk ->
        ensure_supported!(jwk)

      _other ->
        raise ArgumentError,
              "PEM did not contain exactly one parseable key (it was empty, " <>
                "malformed, or carried multiple key entries)"
    end
  end

  defp ensure_supported!(%JOSE.JWK{} = jwk) do
    Attesto.SigningAlg.infer(jwk)
    jwk
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

  Unlike `jwk/1`, this rejects public-only PEMs: they are valid
  verification material, but cannot sign tokens.
  """
  @spec signing_jwk(String.t()) :: JOSE.JWK.t()
  def signing_jwk(pem) when is_binary(pem) do
    jwk = jwk(pem)

    if private_jwk?(jwk) do
      jwk
    else
      raise ArgumentError,
            "expected a private signing key PEM; got public verification material"
    end
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

  # public_pem/1 is a legacy RSA helper; EC/OKP deployments should publish
  # JWK Sets rather than derive an SPKI PEM through this path.
  defp rsa_public_from_private(other) do
    raise ArgumentError,
          "expected an RSA private key for public_pem/1; got a " <>
            "#{inspect(elem(other, 0))} key"
  end

  defp private_jwk?(%JOSE.JWK{} = jwk) do
    jwk
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> Map.get("d")
    |> is_binary()
  end

  defp encode_spki_pem(public_key) do
    :public_key.pem_encode([:public_key.pem_entry_encode(:SubjectPublicKeyInfo, public_key)])
  end

  # `:public_key.pem_encode/1` appends a trailing blank line after the
  # final `-----END ...-----` marker. Trim it so the derived PEM ends with
  # a single newline, matching the on-disk and env-var key shape.
  defp normalize_pem(pem) when is_binary(pem), do: String.trim_trailing(pem) <> "\n"
end
