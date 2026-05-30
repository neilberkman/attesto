defmodule Attesto.DPoP.NonceStore do
  @moduledoc """
  Storage seam for server-issued DPoP nonces (RFC 9449 §8).

  A server that wants to bound a DPoP proof's lifetime issues an opaque,
  time-limited nonce, returns it in a `DPoP-Nonce` response header, and
  requires the client to echo it in the next proof's `nonce` claim. This
  behaviour is where those nonces live: `issue/1` mints one, `valid?/1`
  reports whether a presented nonce is still live.

  `Attesto.DPoP.NonceStore.ETS` is a ready single-node implementation whose
  `validate/1` plugs straight into `Attesto.DPoP.verify_proof/2`'s
  `:nonce_check`. A multi-node deployment implements this over a shared
  store (the nonce a client received from one node must be honoured on
  another).
  """

  @doc """
  Mint and store a fresh nonce valid for `ttl_seconds`, returning the
  opaque nonce string to put in a `DPoP-Nonce` header.
  """
  @callback issue(ttl_seconds :: pos_integer()) :: String.t()

  @doc "Returns true iff `nonce` was issued by this store and has not expired."
  @callback valid?(nonce :: String.t()) :: boolean()
end
