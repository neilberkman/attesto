defmodule Attesto.PKCE do
  @moduledoc """
  RFC 7636 - Proof Key for Code Exchange (PKCE).

  PKCE binds an authorization code to a secret the client generates per
  request, so a stolen code is useless without the matching secret. At the
  authorization request the client sends a `code_challenge` (a transform
  of a freshly generated `code_verifier`); at the token request it sends
  the `code_verifier`, and the server recomputes the challenge and
  compares.

  ## S256 only

  This module implements the `S256` method exclusively:

      code_challenge = base64url(SHA-256(code_verifier)), no padding

  The `plain` method (RFC 7636 §4.2, where the challenge *is* the
  verifier) is deliberately not supported: it offers no protection
  against an attacker who can read the authorization request, and modern
  guidance (OAuth 2.0 Security BCP) requires S256. `verify/3` rejects any
  method other than `"S256"` with `{:error, :unsupported_method}`, so a
  downgrade to `plain` cannot succeed.

  ## Verifier and challenge shapes

    * A `code_verifier` is 43 to 128 characters from the unreserved set
      `[A-Za-z0-9-._~]` (RFC 7636 §4.1).
    * An `S256` `code_challenge` is the canonical 43-character
      base64url-no-pad encoding of a 32-byte SHA-256 digest - the same
      shape `Attesto.Thumbprint` validates.

  The comparison at the token endpoint is constant-time
  (`Attesto.SecureCompare`).
  """

  alias Attesto.SecureCompare
  alias Attesto.Thumbprint

  @s256 "S256"

  # RFC 7636 §4.1: 43..128 characters from the unreserved alphabet.
  @min_verifier_length 43
  @max_verifier_length 128
  @verifier_alphabet ~r/\A[A-Za-z0-9\-._~]+\z/

  @doc "The only supported code-challenge method, `\"S256\"`."
  @spec method() :: String.t()
  def method, do: @s256

  @doc """
  Compute the `S256` `code_challenge` for a `code_verifier`.

  Returns `{:ok, challenge}` for a well-formed verifier (43-128 unreserved
  characters) or `{:error, :invalid_verifier}` otherwise. The challenge is
  `base64url(SHA-256(verifier))` without padding.
  """
  @spec challenge(String.t()) :: {:ok, String.t()} | {:error, :invalid_verifier}
  def challenge(code_verifier) do
    if valid_verifier?(code_verifier) do
      {:ok, Thumbprint.of(code_verifier)}
    else
      {:error, :invalid_verifier}
    end
  end

  @doc """
  Verify a presented `code_verifier` against the stored `code_challenge`.

  `method` defaults to `"S256"` and MUST be `"S256"`; any other value
  (including `"plain"`) returns `{:error, :unsupported_method}`.

  Returns:

    * `:ok` if the verifier is well-formed and its `S256` challenge
      matches `code_challenge` (constant-time compare).
    * `{:error, :unsupported_method}` if `method` is not `"S256"`.
    * `{:error, :invalid_verifier}` if the verifier is not 43-128
      unreserved characters.
    * `{:error, :invalid_challenge}` if the stored challenge is not a
      canonical 43-character base64url SHA-256 value (it could never have
      been produced by `challenge/1`, so a match is impossible and the
      stored value is corrupt).
    * `{:error, :mismatch}` if a well-formed verifier does not match a
      well-formed challenge.
  """
  @spec verify(String.t(), String.t(), String.t()) ::
          :ok
          | {:error, :unsupported_method | :invalid_verifier | :invalid_challenge | :mismatch}
  def verify(code_challenge, code_verifier, method \\ @s256)

  def verify(code_challenge, code_verifier, @s256) do
    cond do
      not valid_verifier?(code_verifier) -> {:error, :invalid_verifier}
      not valid_challenge?(code_challenge) -> {:error, :invalid_challenge}
      SecureCompare.equal?(code_challenge, Thumbprint.of(code_verifier)) -> :ok
      true -> {:error, :mismatch}
    end
  end

  def verify(_code_challenge, _code_verifier, _method), do: {:error, :unsupported_method}

  @doc """
  Returns `true` iff `value` is a well-formed `code_verifier`: 43 to 128
  characters drawn from the RFC 7636 §4.1 unreserved set
  `[A-Za-z0-9-._~]`.
  """
  @spec valid_verifier?(term()) :: boolean()
  def valid_verifier?(value) when is_binary(value) do
    byte_size(value) >= @min_verifier_length and
      byte_size(value) <= @max_verifier_length and
      Regex.match?(@verifier_alphabet, value)
  end

  def valid_verifier?(_), do: false

  @doc """
  Returns `true` iff `value` is a well-formed `S256` `code_challenge`:
  the canonical 43-character base64url-no-pad encoding of a 32-byte
  SHA-256 digest. Delegates to `Attesto.Thumbprint.valid?/1`.
  """
  @spec valid_challenge?(term()) :: boolean()
  def valid_challenge?(value), do: Thumbprint.valid?(value)
end
