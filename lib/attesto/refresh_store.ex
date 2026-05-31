defmodule Attesto.RefreshStore do
  @moduledoc """
  Storage seam for refresh tokens, with the atomic primitive that makes
  reuse detection possible.

  `Attesto.RefreshToken` is pure rotation logic; this behaviour is where
  refresh tokens live and how they are consumed. `Attesto.RefreshStore.ETS`
  is a ready single-node implementation; a production host implements it
  over its database.

  ## The `consume/1` contract (load-bearing)

  Refresh-token rotation (RFC 6749 §10.4, OAuth 2.0 Security BCP) requires
  detecting when an *already-rotated* (consumed) token is presented again:
  that means the token was captured, and the whole token family must be
  revoked. Detecting it reliably needs an **atomic compare-and-set**:
  `consume/1` MUST, in one indivisible step, check whether the token is
  unconsumed and, if so, mark it consumed.

  It returns:

    * `{:ok, record}` - the token existed and was unconsumed; it is now
      consumed. The caller issues the next token in the family.
    * `{:reuse, record}` - the token existed but was **already** consumed.
      The caller MUST `revoke_family/1`. The `record` carries the
      `family_id` to revoke.
    * `:error` - no such token.

  A SQL implementation is `UPDATE refresh_tokens SET consumed = true WHERE
  token_hash = $1 AND consumed = false RETURNING ...`: zero rows updated
  with a row present means reuse. A non-atomic get-then-update would let
  two concurrent rotations both see "unconsumed" and both succeed,
  defeating detection.

  ## Record shape

    * `:token_hash` - `Attesto.Secret.hash/1` of the token (the key).
    * `:family_id` - groups all tokens descended from one authorization;
      revoked together on reuse.
    * `:generation` - 0 for the first token in a family, incremented each
      rotation. Diagnostic.
    * `:data` - the opaque context the host round-trips (subject, scope,
      client, optional DPoP thumbprint, host claims).
    * `:expires_at` - absolute expiry, unix seconds.
    * `:consumed` - whether the token has been rotated already.
    * `:consumed_at` - unix second when the token was rotated, or `nil`.
    * `:successor` - retry data for the immediately issued successor, or `nil`.
  """

  @type token_hash :: String.t()
  @type family_id :: String.t()

  @type entry :: %{
          required(:token_hash) => token_hash(),
          required(:family_id) => family_id(),
          required(:generation) => non_neg_integer(),
          required(:data) => map(),
          required(:expires_at) => integer(),
          required(:consumed) => boolean(),
          optional(:consumed_at) => integer() | nil,
          optional(:successor) => map() | nil
        }

  @doc """
  Persist a new (unconsumed) refresh-token record.

  Returns `{:error, :family_revoked}` if the record's `family_id` has been
  revoked (see `revoke_family/1`); the row MUST NOT be stored in that
  case. This closes a concurrency race: a rotation that wins the atomic
  `consume/1` but whose successor `insert/1` lands *after* a concurrent
  reuse revoked the family would otherwise leave a live successor in a
  revoked family. Revocation is therefore sticky - it rejects later
  inserts, not just the rows present at revoke time.
  """
  @callback insert(entry()) :: :ok | {:error, :family_revoked}

  @doc """
  Non-consuming read of the record for `token_hash`, or `:error` if
  absent. Used to validate a rotation (expiry, DPoP binding) and to detect
  a replayed already-consumed token BEFORE the atomic `consume/1` claims
  it, so a recoverable validation failure does not burn the token.
  """
  @callback get(token_hash()) :: {:ok, entry()} | :error

  @doc """
  Atomically mark the token consumed if it was not already. See the
  moduledoc for the required semantics and the three return values. This
  is the claim step, run only once a rotation has otherwise validated; it
  also closes the read-then-claim race (a concurrent rotation that claimed
  the token first surfaces here as `{:reuse, record}`).
  """
  @callback consume(token_hash(), keyword()) :: {:ok, entry()} | {:reuse, entry()} | :error

  @doc """
  Record the successor minted from an already-consumed parent.

  Used for refresh-rotation idempotency: if the response carrying the new
  refresh token is lost and the same client immediately retries the old token,
  `Attesto.RefreshToken.rotate/3` may return the same successor instead of
  revoking the family. Stores that cannot retain the successor safely MUST fail
  closed by returning `:error`; rotation still succeeds, but a later retry will
  be treated as reuse.
  """
  @callback remember_successor(token_hash(), map(), keyword()) :: :ok | :error

  @doc """
  Revoke a token family: remove every token in `family_id` AND mark the
  family revoked so a subsequent `insert/1` for it is refused (sticky
  revocation; see `insert/1`). Idempotent - revoking an already-revoked or
  unknown family is a no-op `:ok`.
  """
  @callback revoke_family(family_id()) :: :ok
end
