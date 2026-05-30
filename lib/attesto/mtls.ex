defmodule Attesto.MTLS do
  @moduledoc """
  RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and
  Certificate-Bound Access Tokens.

  A protected resource that supports mTLS-bound access tokens MUST verify
  that the access token's confirmation claim (RFC 7800 `cnf.x5t#S256`)
  matches the SHA-256 thumbprint of the client certificate presented in
  the same TLS connection. This module computes that thumbprint and
  recognises the binding shape.

  ## Thumbprint definition

  Per RFC 8705 §3.1 the `x5t#S256` value is

      base64url(SHA-256(DER-encoded certificate)), no padding

  which is the canonical shape validated by `Attesto.Thumbprint`.

  ## Why we round-trip through `:public_key.pkix_decode_cert/2`

  `compute_thumbprint/1` only digests its input after confirming that the
  bytes parse as an X.509 certificate. A caller that fed in a random
  binary would otherwise produce a "thumbprint" that no real client
  certificate could ever match - silently turning the binding into a
  permanent reject, or (if the binary came from an unauthenticated
  source) into an attacker-controlled match. Fail closed at the source.

  This module is framework-agnostic: no Plug, no database, no application
  config. It is a pure function of the certificate bytes. A resource
  server composes `Attesto.Token.verify/3` with `compute_thumbprint/1`
  applied to the DER bytes its TLS layer surfaces (e.g.
  `:ssl.peercert/1`).

  ## Where the binding may be *issued*

  Whether the listener is even allowed to issue mTLS-bound tokens (the
  TLS layer is directly terminated and the peer certificate is genuinely
  the client's, rather than a reverse-proxy socket) is a deployment fact
  the **host application** owns. Attesto does not read it from config;
  the caller decides whether to pass an mTLS thumbprint to
  `Attesto.Token.mint/2` at all.
  """

  alias Attesto.Thumbprint

  @type thumbprint :: String.t()

  @doc """
  Compute the RFC 8705 §3.1 `x5t#S256` thumbprint of an X.509 client
  certificate from its DER encoding.

  Returns `{:ok, thumbprint}` if the bytes parse as a certificate;
  `{:error, :invalid_certificate}` otherwise. The certificate is NOT
  validated against any trust store, expiry, or revocation status - that
  is the TLS terminator's responsibility. This function only ensures the
  bytes ARE a certificate (so we never emit a thumbprint for arbitrary
  attacker-controlled bytes) and computes the digest.
  """
  @spec compute_thumbprint(binary()) :: {:ok, thumbprint()} | {:error, :invalid_certificate}
  def compute_thumbprint(der) when is_binary(der) and byte_size(der) > 0 do
    if parseable_cert?(der) do
      {:ok, Thumbprint.of(der)}
    else
      {:error, :invalid_certificate}
    end
  end

  def compute_thumbprint(_), do: {:error, :invalid_certificate}

  @doc """
  Returns `true` iff `value` is a syntactically-valid `x5t#S256`
  thumbprint: the canonical base64url-no-pad encoding of a 32-byte
  SHA-256 digest. Delegates to `Attesto.Thumbprint.valid?/1`.
  """
  @spec thumbprint_shape?(term()) :: boolean()
  def thumbprint_shape?(value), do: Thumbprint.valid?(value)

  @doc """
  Returns `true` iff the given access-token claims map advertises an
  mTLS binding via the RFC 8705 `cnf.x5t#S256` confirmation claim.
  Tolerates any non-empty string value (full shape validation happens in
  `Attesto.Token.verify/3`).
  """
  @spec mtls_bound?(map()) :: boolean()
  def mtls_bound?(%{"cnf" => %{"x5t#S256" => t}}) when is_binary(t) and t != "", do: true
  def mtls_bound?(_), do: false

  @doc """
  The expected length, in characters, of a well-formed `x5t#S256`
  thumbprint.
  """
  @spec thumbprint_length() :: pos_integer()
  def thumbprint_length, do: Thumbprint.length()

  # `:public_key.pkix_decode_cert/2` raises a MatchError for any input
  # that isn't a parseable X.509 certificate (bad ASN.1, empty binary,
  # random garbage). We rescue both the `error` and `throw`/`exit` paths
  # and collapse them into a single boolean so callers cannot fingerprint
  # the parser.
  defp parseable_cert?(der) do
    _ = :public_key.pkix_decode_cert(der, :plain)
    true
  rescue
    _ -> false
  catch
    _, _ -> false
  end
end
