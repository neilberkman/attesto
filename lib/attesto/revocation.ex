defmodule Attesto.Revocation do
  @moduledoc """
  RFC 7009 - OAuth 2.0 Token Revocation, for refresh tokens.

  Revoking a refresh token revokes its entire family (every token
  descended from the same authorization), the same machinery refresh
  rotation uses for reuse detection. This module is the deliberate
  revocation entry point; it runs over an `Attesto.RefreshStore`.

  ## No-existence oracle (RFC 7009 §2.2)

  An invalid, expired, or unknown token does **not** produce an error:
  `revoke/3` returns `:ok` regardless of whether the token existed. A
  revocation endpoint must not let a caller probe which tokens are live,
  so revoking a token the store has never seen is indistinguishable from
  revoking a real one.

  ## Client binding (RFC 7009 §2.1)

  When the token carries a `client_id`, revocation is fail-closed: the
  caller MUST present a matching `:client_id` or the call returns
  `{:error, :unauthorized_client}`, so one client cannot revoke another
  client's tokens. A caller that cannot authenticate the client passes
  `allow_missing_client_id?: true`. A token issued without a client
  binding skips the check.

  ## Access tokens

  Attesto access tokens are stateless, short-lived JWTs, so there is no
  per-token revocation list to consult; revoking them is a host concern
  (rely on their short TTL, or maintain a `jti` denylist the resource
  server checks). This module revokes the stateful, family-backed refresh
  credential, which is what RFC 7009 revocation is primarily for.
  """

  alias Attesto.Secret

  @type revoke_error :: :unauthorized_client

  @doc """
  Revoke the refresh token `token` (and its whole family) via `store`.

  Returns `:ok` whether or not the token existed (no-existence oracle).
  Returns `{:error, :unauthorized_client}` only when the token carries a
  `client_id` and the presented `:client_id` does not match (or is absent
  without `allow_missing_client_id?: true`).

  Options: `:client_id` (the authenticated revoking client) and
  `:allow_missing_client_id?`.
  """
  @spec revoke(module(), String.t(), keyword()) :: :ok | {:error, revoke_error()}
  def revoke(store, token, opts \\ []) when is_atom(store) and is_binary(token) and is_list(opts) do
    case store.get(Secret.hash(token)) do
      {:ok, record} ->
        revoke_present(store, record, opts)

      :error ->
        # RFC 7009 §2.2: an invalid token is not an error.
        :ok
    end
  end

  # An expired record is, for the no-existence-oracle rule, the same as an
  # absent one: returning `{:error, :unauthorized_client}` for a wrong or
  # missing client here would let a caller tell "this token once existed
  # and is now expired" apart from "this token was never issued". Treat an
  # expired record as absent - `:ok`, no client check, no family revoke
  # (its family is already dead by TTL).
  defp revoke_present(store, record, opts) do
    if expired?(record) do
      :ok
    else
      with :ok <- check_client(record.data, opts) do
        :ok = store.revoke_family(record.family_id)
        :ok
      end
    end
  end

  defp expired?(%{expires_at: expires_at}) when is_integer(expires_at) do
    expires_at <= System.system_time(:second)
  end

  defp expired?(_record), do: false

  defp check_client(%{client_id: stored}, opts) when is_binary(stored) do
    case Keyword.get(opts, :client_id) do
      nil ->
        if Keyword.get(opts, :allow_missing_client_id?, false),
          do: :ok,
          else: {:error, :unauthorized_client}

      ^stored ->
        :ok

      _ ->
        {:error, :unauthorized_client}
    end
  end

  defp check_client(_data, _opts), do: :ok
end
