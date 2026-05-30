defmodule Attesto.SecureCompare do
  @moduledoc """
  Constant-time comparison of two binaries.

  Used wherever an attacker-controlled value is checked against a secret
  or a derived digest (a DPoP `ath`, a PKCE challenge) and a
  short-circuiting `==` would leak information through timing.
  """

  @doc """
  Returns `true` iff `a` and `b` are byte-identical, comparing in
  constant time.

  `:crypto.hash_equals/2` requires equal-length inputs, and at least one
  operand here is attacker-controlled, so the length is gated first. The
  length check is not itself timing-sensitive in the cases this is used
  for: the operands are fixed-length base64url digests, so a length
  mismatch only ever means a malformed input, not a near-miss secret.
  """
  @spec equal?(binary(), binary()) :: boolean()
  def equal?(a, b) when is_binary(a) and is_binary(b) do
    byte_size(a) == byte_size(b) and :crypto.hash_equals(a, b)
  end

  def equal?(_, _), do: false
end
