defmodule Attesto.AuthorizationCode do
  @moduledoc """
  RFC 6749 §4.1 authorization-code grant, with mandatory PKCE (RFC 7636,
  S256) and optional DPoP binding of the code (RFC 9449 §10).

  This module is pure logic over a `Attesto.CodeStore`: `issue/3` mints a
  single-use code at the authorization endpoint, `redeem/4` validates and
  consumes it at the token endpoint and returns the grant context the host
  uses to mint an access token. The store decides where codes live and
  guarantees single use; everything validated here (expiry, exact
  redirect-URI match, the PKCE transform, the DPoP key binding) is
  protocol.

  ## PKCE is mandatory

  `issue/3` requires a valid S256 `code_challenge`; there is no
  PKCE-less path. A redemption without a matching `code_verifier` fails.
  This closes authorization-code interception for public clients and is
  the modern default (OAuth 2.0 Security BCP). Only S256 is accepted
  (see `Attesto.PKCE`).

  ## Single use even on failure

  `redeem/4` consumes the code via `c:Attesto.CodeStore.take/1` **before**
  validating it, so a presented code is spent whether or not the
  redemption succeeds. An attacker who captures a code cannot make
  repeated validation attempts against it.

  ## DPoP-bound codes

  If `issue/3` is given a `:dpop_jkt`, the code is bound to that DPoP key
  (RFC 9449 §10): redemption MUST present the same `:dpop_jkt` (the
  thumbprint of the key in the token-request's DPoP proof) or it is
  rejected. A code minted without a binding MUST be redeemed without one.
  """

  alias Attesto.AuthorizationCode.Grant
  alias Attesto.PKCE
  alias Attesto.Scope
  alias Attesto.Secret
  alias Attesto.Thumbprint

  @default_ttl_seconds 60

  @type issue_attrs :: %{
          required(:client_id) => String.t(),
          required(:redirect_uri) => String.t(),
          required(:code_challenge) => String.t(),
          required(:subject) => String.t(),
          optional(:scope) => [String.t()],
          optional(:code_challenge_method) => String.t(),
          optional(:dpop_jkt) => String.t() | nil,
          optional(:claims) => map()
        }

  @type issue_error ::
          :invalid_client_id
          | :invalid_redirect_uri
          | :invalid_code_challenge
          | :unsupported_code_challenge_method
          | :invalid_subject
          | :invalid_scope
          | :invalid_dpop_jkt
          | :invalid_claims

  @type redeem_params :: %{
          required(:redirect_uri) => String.t(),
          required(:code_verifier) => String.t(),
          optional(:client_id) => String.t(),
          optional(:dpop_jkt) => String.t() | nil
        }

  @type redeem_error ::
          :invalid_grant
          | :expired
          | :client_required
          | :client_mismatch
          | :redirect_uri_mismatch
          | :pkce_failed
          | :dpop_proof_required
          | :dpop_proof_unexpected
          | :dpop_binding_mismatch

  @doc """
  Mint a single-use authorization code and persist it via `store`.

  `attrs` MUST carry `:client_id`, `:redirect_uri`, a valid S256
  `:code_challenge`, and `:subject`. Optional `:scope` (a list of
  strings, default `[]`), `:code_challenge_method` (must be `"S256"` if
  given), `:dpop_jkt` (binds the code to a DPoP key), and `:claims` (an
  opaque host context map round-tripped to `redeem/4`).

  Options: `:ttl` (seconds the code is valid, default
  #{@default_ttl_seconds}) and `:now` (clock override).

  Returns `{:ok, code}` with the plaintext code to hand the client. Only
  the code's hash is stored. Returns `{:error, reason}` on malformed
  `attrs`.
  """
  @spec issue(module(), issue_attrs(), keyword()) :: {:ok, String.t()} | {:error, issue_error()}
  def issue(store, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    with :ok <- validate_method(Map.get(attrs, :code_challenge_method, "S256")),
         {:ok, data} <- normalize_issue_attrs(attrs) do
      code = Secret.generate()
      ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)

      :ok =
        store.put(%{
          code_hash: Secret.hash(code),
          data: data,
          expires_at: unix_now(opts) + ttl
        })

      {:ok, code}
    end
  end

  @doc """
  Validate and consume a code at the token endpoint.

  `params` MUST carry the `:redirect_uri` (matched exactly against the one
  in the authorization request), the `:code_verifier` (checked against the
  stored PKCE challenge), and the `:client_id` of the redeeming client. By
  default client binding is fail-closed: since every stored code carries a
  `client_id`, redemption MUST present one (`:client_required` if absent,
  `:client_mismatch` if wrong) - this stops a code issued to one client
  being redeemed by another (RFC 6749 §4.1.3). A caller that cannot
  authenticate the client and relies on PKCE alone passes
  `allow_missing_client_id?: true` in `opts`. `:dpop_jkt` is required iff
  the code was DPoP-bound at `issue/3`.

  The code is consumed (single use) before validation. Returns
  `{:ok, %Attesto.AuthorizationCode.Grant{}}` with the validated grant
  context, or `{:error, reason}`.
  """
  @spec redeem(module(), String.t(), redeem_params(), keyword()) ::
          {:ok, Grant.t()} | {:error, redeem_error()}
  def redeem(store, code, params, opts \\ []) when is_atom(store) and is_binary(code) and is_map(params) do
    case store.take(Secret.hash(code)) do
      {:ok, record} ->
        validate_redemption(record, params, opts)

      :error ->
        {:error, :invalid_grant}
    end
  end

  defp validate_redemption(%{data: data, expires_at: expires_at}, params, opts) do
    with :ok <- check_expiry(expires_at, opts),
         :ok <- check_client(data, params, opts),
         :ok <- check_redirect_uri(data, params),
         :ok <- check_pkce(data, params),
         :ok <- check_dpop(data, params) do
      {:ok, Grant.from_data(data)}
    end
  end

  # RFC 6749 §4.1.3: the code must be redeemed by the client it was issued
  # to. Fail closed by default - a stored code always carries a
  # `client_id`, so redemption MUST present a matching one
  # (`:client_required` when absent, `:client_mismatch` when wrong). A
  # caller that genuinely cannot authenticate the client (and relies on
  # PKCE alone) opts out explicitly with `allow_missing_client_id?: true`.
  defp check_client(%{client_id: stored}, params, opts) do
    case Map.get(params, :client_id) do
      nil -> if allow_missing_client?(opts), do: :ok, else: {:error, :client_required}
      ^stored -> :ok
      _ -> {:error, :client_mismatch}
    end
  end

  defp allow_missing_client?(opts), do: Keyword.get(opts, :allow_missing_client_id?, false)

  # ----- issue validation -----

  defp validate_method("S256"), do: :ok
  defp validate_method(_), do: {:error, :unsupported_code_challenge_method}

  defp normalize_issue_attrs(attrs) do
    scope = Map.get(attrs, :scope, [])
    dpop_jkt = Map.get(attrs, :dpop_jkt)

    cond do
      not non_empty_binary?(Map.get(attrs, :client_id)) ->
        {:error, :invalid_client_id}

      not non_empty_binary?(Map.get(attrs, :redirect_uri)) ->
        {:error, :invalid_redirect_uri}

      not PKCE.valid_challenge?(Map.get(attrs, :code_challenge)) ->
        {:error, :invalid_code_challenge}

      not non_empty_binary?(Map.get(attrs, :subject)) ->
        {:error, :invalid_subject}

      not valid_scope?(scope) ->
        {:error, :invalid_scope}

      not valid_optional_jkt?(dpop_jkt) ->
        {:error, :invalid_dpop_jkt}

      not is_map(Map.get(attrs, :claims, %{})) ->
        {:error, :invalid_claims}

      true ->
        {:ok,
         %{
           client_id: attrs.client_id,
           redirect_uri: attrs.redirect_uri,
           code_challenge: attrs.code_challenge,
           subject: attrs.subject,
           scope: scope,
           dpop_jkt: dpop_jkt,
           claims: Map.get(attrs, :claims, %{})
         }}
    end
  end

  # ----- redeem validation -----

  defp check_expiry(expires_at, opts) do
    if expires_at > unix_now(opts), do: :ok, else: {:error, :expired}
  end

  # RFC 6749 §3.1.2 / §4.1.3: the redirect URI is compared by exact
  # string match, never normalised, to deny open-redirect smuggling.
  defp check_redirect_uri(%{redirect_uri: registered}, %{redirect_uri: presented}) do
    if is_binary(presented) and presented == registered,
      do: :ok,
      else: {:error, :redirect_uri_mismatch}
  end

  defp check_redirect_uri(_data, _params), do: {:error, :redirect_uri_mismatch}

  defp check_pkce(%{code_challenge: challenge}, %{code_verifier: verifier}) do
    case PKCE.verify(challenge, verifier) do
      :ok -> :ok
      # Collapse every PKCE failure to one error so a redemption cannot
      # distinguish "wrong verifier" from "malformed verifier".
      {:error, _} -> {:error, :pkce_failed}
    end
  end

  defp check_pkce(_data, _params), do: {:error, :pkce_failed}

  # Mirrors the token `cnf` binding matrix: a bound code requires a
  # matching proof, an unbound code forbids one.
  defp check_dpop(%{dpop_jkt: bound}, params) when is_binary(bound) do
    case Map.get(params, :dpop_jkt) do
      # Only a wholly absent proof is "required"; any present-but-wrong
      # value (mismatched binary or malformed) is a binding mismatch.
      nil -> {:error, :dpop_proof_required}
      ^bound -> :ok
      _ -> {:error, :dpop_binding_mismatch}
    end
  end

  defp check_dpop(_data, params) do
    case Map.get(params, :dpop_jkt) do
      nil -> :ok
      _ -> {:error, :dpop_proof_unexpected}
    end
  end

  # ----- helpers -----

  defp non_empty_binary?(v), do: is_binary(v) and v != ""
  defp valid_scope?(scope), do: is_list(scope) and Enum.all?(scope, &Scope.valid_token?/1)
  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(jkt), do: Thumbprint.valid?(jkt)

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end
end
