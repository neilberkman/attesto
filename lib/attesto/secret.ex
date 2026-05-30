defmodule Attesto.Secret do
  @moduledoc """
  Generate and hash the opaque secrets that back stateful grants.

  Authorization codes and refresh tokens are high-entropy random strings
  handed to a client once. The server never needs the plaintext again, so
  it persists only a hash: a leaked code/refresh store then yields no
  usable credentials. This module is the single place that generates such
  secrets and computes their lookup hash.

    * `generate/1` returns a fresh base64url-no-pad secret with the given
      entropy (default 32 bytes = 256 bits).
    * `hash/1` returns the SHA-256 base64url-no-pad digest used as the
      storage key. Lookups hash the presented secret and compare, so the
      store is keyed by `hash/1` output, never by plaintext.

  Comparisons against a stored value should go through
  `Attesto.SecureCompare` to stay constant-time.
  """

  alias Attesto.Thumbprint

  @default_bytes 32

  @doc """
  Generate a fresh random secret as a base64url-no-pad string with
  `bytes` of entropy (default #{@default_bytes}).
  """
  @spec generate(pos_integer()) :: String.t()
  def generate(bytes \\ @default_bytes) when is_integer(bytes) and bytes > 0 do
    bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  @doc """
  The SHA-256 base64url-no-pad hash of `secret`, used as its storage key.
  """
  @spec hash(String.t()) :: String.t()
  def hash(secret) when is_binary(secret), do: Thumbprint.of(secret)
end
