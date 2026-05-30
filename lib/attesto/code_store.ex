defmodule Attesto.CodeStore do
  @moduledoc """
  Storage seam for authorization codes.

  `Attesto.AuthorizationCode` is pure: it generates a code, hashes it, and
  validates a redemption, but it never decides *where* the code lives.
  That is this behaviour. A host implements it over whatever store fits
  (Postgres, Redis, ETS); `Attesto.CodeStore.ETS` is a ready single-node
  implementation.

  ## The single-use contract (load-bearing)

  `take/1` MUST be atomic: it returns the record for `code_hash` **and
  removes it** in one indivisible step, so two concurrent redemptions of
  the same code cannot both succeed. Authorization codes are single-use
  (RFC 6749 §4.1.2); a store that let `take/1` race would let a captured
  code be replayed. A SQL implementation uses
  `DELETE ... WHERE code_hash = $1 RETURNING ...`; an ETS implementation
  uses `:ets.take/2`.

  The code is consumed by `take/1` even if `Attesto.AuthorizationCode`
  then rejects the redemption (wrong redirect URI, failed PKCE): a code
  that has been presented once is spent, which denies an attacker repeated
  validation attempts against a stolen code.

  ## Record shape

  A stored record is a map with:

    * `:code_hash` - the `Attesto.Secret.hash/1` of the code (the key).
    * `:data` - the opaque grant context the host round-trips
      (client, redirect URI, scope, PKCE challenge, optional DPoP
      thumbprint, subject, and any host claims).
    * `:expires_at` - absolute expiry, unix seconds. The store MAY evict
      expired records, but `Attesto.AuthorizationCode` re-checks expiry
      after `take/1`, so eviction timing is not security-critical.
  """

  @type code_hash :: String.t()

  @type entry :: %{
          required(:code_hash) => code_hash(),
          required(:data) => map(),
          required(:expires_at) => integer()
        }

  @doc "Persist a code record."
  @callback put(entry()) :: :ok

  @doc """
  Atomically fetch and delete the record for `code_hash`. Returns
  `{:ok, record}` if present (now removed), or `:error` if absent. MUST be
  a single indivisible operation to preserve single use.
  """
  @callback take(code_hash()) :: {:ok, entry()} | :error
end
