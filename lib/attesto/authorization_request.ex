defmodule Attesto.AuthorizationRequest do
  @moduledoc """
  Authorization endpoint request validation (RFC 6749 §4.1.1, OIDC Core
  §3.1.2.1, RFC 7636 §4.3).

  This module validates the *protocol* shape of an authorization request that
  the transport layer has already parsed out of the query string. It checks the
  `response_type`, the presence of `client_id` and `redirect_uri`, the requested
  scope (surfacing whether the OpenID Connect `openid` scope was requested), and
  the PKCE parameters (`code_challenge` + `code_challenge_method`). It carries
  `state`, `nonce`, `claims`, and the optional `prompt` / `max_age` / `acr_values`
  parameters through to the normalized result.

  It deliberately does NOT:

    * authenticate the resource owner or render consent (host policy, performed
      in the Phoenix layer);
    * decide whether the `client_id` exists, beyond requiring it to be present;
    * issue an authorization code (`Attesto.AuthorizationCode.issue/3` does that,
      consuming the normalized request this module returns).

  It DOES check `redirect_uri` against the registered set the caller passes in
  `:registered_redirect_uris` by exact string match (RFC 6749 §3.1.2.3, OIDC
  Core §3.1.2.1): the registered set is a fact the host supplies, not a policy
  decision this module makes.

  ## Error disposition (OIDC Core §3.1.2.6, RFC 6749 §4.1.2.1)

  RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6 split authorization errors into two
  classes by *where the error may be reported*:

    * `{:error, {:direct, reason}}` - the request `client_id` or `redirect_uri`
      is missing or invalid. The authorization server MUST NOT redirect back to
      the supplied URI (it is untrusted); the error is shown directly to the
      user agent. Reasons: `:invalid_client_id`, `:missing_redirect_uri`,
      `:invalid_redirect_uri`, `:redirect_uri_not_registered`.

    * `{:error, {:redirect, error}}` - the `client_id`/`redirect_uri` pair is
      trusted but some other parameter is invalid. The server redirects back to
      the validated `redirect_uri` with an `error` (and `error_description`)
      query parameter, echoing `state` when present. The `error` map carries:
      `:error` (the RFC 6749 §4.1.2.1 code), `:error_description`,
      `:redirect_uri`, and `:state`.

  The Phoenix layer turns each class into the correct HTTP response; this core
  module only classifies.
  """

  alias Attesto.PKCE
  alias Attesto.RequestObject
  alias Attesto.Scope

  @response_type_code "code"
  @openid_scope "openid"
  @plain_method "plain"

  # OIDC Core §3.1.2.1: the complete, fixed set of prompt values. Any token
  # outside this set is an invalid_request.
  @prompt_values ["none", "login", "consent", "select_account"]

  @default_require_nonce false

  # RFC 7636 / RFC 9700: PKCE is required by default. The caller may relax it
  # (only ever for confidential clients; public clients MUST use PKCE per
  # RFC 9700 §2.1.1) by passing `require_pkce: false`. Even when relaxed, a
  # `code_challenge` that IS present is still fully enforced (S256, no `plain`).
  @default_require_pkce true

  @typedoc """
  A normalized, validated authorization request.

  The binding fields (`client_id`, `redirect_uri`, `scope`, `code_challenge`,
  `code_challenge_method`, `nonce`) line up with the attrs
  `Attesto.AuthorizationCode.issue/3` consumes.
  """
  @type t :: %__MODULE__{
          response_type: String.t(),
          client_id: String.t(),
          redirect_uri: String.t(),
          scope: [String.t()],
          openid?: boolean(),
          state: String.t() | nil,
          nonce: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil,
          prompt: [String.t()],
          max_age: non_neg_integer() | nil,
          claims: map(),
          acr_values: [String.t()]
        }

  # `code_challenge`/`code_challenge_method` are NOT enforced keys: PKCE is
  # required by default but may be relaxed for a confidential client via the
  # `:require_pkce` option (RFC 9700 keeps PKCE MUST only for public clients),
  # in which case a validated request carries no challenge. They default to nil
  # in the struct.
  @enforce_keys [
    :response_type,
    :client_id,
    :redirect_uri
  ]
  defstruct [
    :client_id,
    :code_challenge,
    :code_challenge_method,
    :claims,
    :max_age,
    :nonce,
    :redirect_uri,
    :response_type,
    :state,
    acr_values: [],
    openid?: false,
    prompt: [],
    scope: []
  ]

  @typedoc "A redirectable authorization error (RFC 6749 §4.1.2.1)."
  @type redirect_error :: %{
          error: String.t(),
          error_description: String.t(),
          redirect_uri: String.t(),
          state: String.t() | nil
        }

  @typedoc "The classification of a validation failure (OIDC Core §3.1.2.6)."
  @type error ::
          {:direct,
           :invalid_client_id
           | :missing_redirect_uri
           | :invalid_redirect_uri
           | :redirect_uri_not_registered}
          | {:redirect, redirect_error()}

  @doc """
  Validate a parsed authorization request parameter map (RFC 6749 §4.1.1,
  OIDC Core §3.1.2.1, RFC 7636 §4.3).

  `params` is a string-keyed map of the authorization request query parameters.

  ## Options

    * `:registered_redirect_uris` (required) - the list of redirect URIs
      registered for the client. The request `redirect_uri` MUST be an exact
      string match against one of these (RFC 6749 §3.1.2.3, OIDC Core
      §3.1.2.1). An empty list rejects every request with
      `{:direct, :redirect_uri_not_registered}`.

    * `:require_nonce` (optional, default `false`) - when `true`, a request with
      no `nonce` is rejected with a redirectable `invalid_request` error (OIDC
      Core §3.1.2.1). When `false`, `nonce` stays OPTIONAL and is carried through
      unenforced (RFC 6749 keeps `code` at SHOULD). The host sets this per its
      own OP policy.

    * `:require_pkce` (optional, default `true`) - when `true`, a request with no
      `code_challenge` is rejected with a redirectable `invalid_request` error
      (RFC 7636 §4.3). When `false`, an absent `code_challenge` is permitted and
      the validated request carries none. The caller MUST pass `false` only for a
      confidential client: RFC 9700 §2.1.1 keeps PKCE a MUST for public clients.
      A `code_challenge` that IS present is fully enforced (S256, no `plain`)
      regardless of this flag - presence means the client opted into PKCE, so a
      downgrade is always rejected.

  Returns `{:ok, %Attesto.AuthorizationRequest{}}` or `{:error, error()}`, where
  `error()` is classified per the moduledoc.

  The `client_id` / `redirect_uri` checks run first, because their failure is
  non-redirectable (OIDC Core §3.1.2.6): only once a trusted `redirect_uri` is
  established may any further error be reported by redirecting to it.
  """
  @spec validate(map(), keyword()) :: {:ok, t()} | {:error, error()}
  def validate(params, opts) when is_map(params) and is_list(opts) do
    registered = Keyword.fetch!(opts, :registered_redirect_uris)
    require_nonce = Keyword.get(opts, :require_nonce, @default_require_nonce)
    require_pkce = Keyword.get(opts, :require_pkce, @default_require_pkce)

    with {:ok, params} <- merge_request_object(params, opts),
         {:ok, client_id} <- validate_client_id(params),
         {:ok, redirect_uri} <- validate_redirect_uri(params, registered) do
      # From here on, redirect_uri is trusted: report further errors by
      # redirecting to it (RFC 6749 §4.1.2.1).
      validate_redirectable(params, client_id, redirect_uri, require_nonce, require_pkce)
    end
  end

  defp merge_request_object(%{"request" => request} = params, opts) when is_binary(request) and request != "" do
    with {:ok, jwks} <- fetch_request_object_jwks(opts),
         {:ok, object_params} <-
           RequestObject.verify(request, jwks,
             issuer: Map.get(params, "client_id"),
             audience: Keyword.get(opts, :request_object_audience)
           ) do
      {:ok, Map.merge(params, object_params)}
    else
      {:error, :request_not_supported} ->
        redirect_request_object_error(params, "request_not_supported", "request object is not supported", opts)

      _ ->
        redirect_request_object_error(params, "invalid_request_object", "request object is invalid", opts)
    end
  end

  defp merge_request_object(params, _opts), do: {:ok, params}

  defp redirect_request_object_error(params, error, description, opts) do
    case validate_redirect_uri(params, Keyword.fetch!(opts, :registered_redirect_uris)) do
      {:ok, redirect_uri} ->
        state = string_or_nil(Map.get(params, "state"))

        {:error,
         redirect_error(
           error,
           description,
           redirect_uri,
           state
         )}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_request_object_jwks(opts) do
    case Keyword.get(opts, :request_object_jwks) do
      nil -> {:error, :missing_request_object_jwks}
      jwks -> {:ok, jwks}
    end
  end

  # --- Non-redirectable checks (OIDC Core §3.1.2.6) ---

  # RFC 6749 §4.1.1: client_id is REQUIRED. A missing or non-string client_id
  # cannot be trusted, so the error is reported directly, not by redirect.
  defp validate_client_id(params) do
    case Map.get(params, "client_id") do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, {:direct, :invalid_client_id}}
    end
  end

  # RFC 6749 §3.1.2.3 / OIDC Core §3.1.2.1: redirect_uri is REQUIRED for OIDC
  # and MUST exactly match one of the client's registered URIs. A mismatch is
  # non-redirectable because the supplied URI is untrusted (OIDC Core §3.1.2.6).
  defp validate_redirect_uri(params, registered) do
    case Map.get(params, "redirect_uri") do
      uri when is_binary(uri) and uri != "" ->
        if registered?(uri, registered) do
          {:ok, uri}
        else
          {:error, {:direct, :redirect_uri_not_registered}}
        end

      nil ->
        {:error, {:direct, :missing_redirect_uri}}

      _ ->
        {:error, {:direct, :invalid_redirect_uri}}
    end
  end

  # Exact string comparison (RFC 6749 §3.1.2.3 simple string match). No
  # normalization, no prefix matching: a registered URI must be reproduced
  # byte-for-byte, the same discipline AuthorizationCode applies at redemption.
  defp registered?(uri, registered) when is_list(registered) do
    Enum.any?(registered, fn candidate -> is_binary(candidate) and candidate == uri end)
  end

  # --- Redirectable checks (RFC 6749 §4.1.2.1) ---

  defp validate_redirectable(params, client_id, redirect_uri, require_nonce, require_pkce) do
    state = string_or_nil(Map.get(params, "state"))

    with :ok <- validate_request_object_params(params, redirect_uri, state),
         :ok <- validate_response_type(params, redirect_uri, state),
         {:ok, scope} <- validate_scope(params, redirect_uri, state),
         {:ok, code_challenge, method} <- validate_pkce(params, require_pkce, redirect_uri, state),
         {:ok, max_age} <- validate_max_age(params, redirect_uri, state),
         {:ok, prompt} <- validate_prompt(params, redirect_uri, state),
         {:ok, claims} <- validate_claims(params, redirect_uri, state),
         {:ok, nonce} <- validate_nonce(params, require_nonce, redirect_uri, state) do
      {:ok,
       %__MODULE__{
         response_type: @response_type_code,
         client_id: client_id,
         redirect_uri: redirect_uri,
         scope: scope,
         openid?: @openid_scope in scope,
         state: state,
         nonce: nonce,
         code_challenge: code_challenge,
         code_challenge_method: method,
         prompt: prompt,
         max_age: max_age,
         claims: claims,
         acr_values: parse_space_list(Map.get(params, "acr_values"))
       }}
    end
  end

  # OpenID Connect Core §6 / §3.1.2.6: request objects are verified and merged
  # before this point when the caller supplies `:request_object_jwks`. A raw
  # `request_uri` is still rejected here unless the transport layer has already
  # resolved it (PAR) into normal params.
  defp validate_request_object_params(params, redirect_uri, state) do
    if present?(Map.get(params, "request_uri")) do
      {:error,
       redirect_error(
         "request_uri_not_supported",
         "request_uri parameter is not supported",
         redirect_uri,
         state
       )}
    else
      :ok
    end
  end

  # RFC 6749 §4.1.1 / OIDC Core §3.1.2.1: response_type is REQUIRED and must be
  # "code" for the authorization-code flow. Any other value is the
  # "unsupported_response_type" error (RFC 6749 §4.1.2.1); a wholly absent one
  # is "invalid_request".
  defp validate_response_type(params, redirect_uri, state) do
    case Map.get(params, "response_type") do
      @response_type_code ->
        :ok

      nil ->
        {:error, redirect_error("invalid_request", "response_type is required", redirect_uri, state)}

      _ ->
        {:error,
         redirect_error(
           "unsupported_response_type",
           "only response_type=code is supported",
           redirect_uri,
           state
         )}
    end
  end

  # RFC 6749 §3.3: scope is OPTIONAL and space-delimited. Each token must satisfy
  # the RFC 6749 Appendix A scope-token ABNF (`Attesto.Scope.valid_token?/1`); an
  # out-of-ABNF token is the "invalid_scope" error (RFC 6749 §4.1.2.1). The
  # OpenID Connect `openid` scope (OIDC Core §3.1.2.1) is surfaced via `openid?`
  # so the host can branch OIDC vs plain OAuth without re-parsing.
  defp validate_scope(params, redirect_uri, state) do
    case Map.get(params, "scope") do
      nil ->
        {:ok, []}

      value when is_binary(value) ->
        tokens = String.split(value, " ", trim: true)

        if Enum.all?(tokens, &Scope.valid_token?/1) do
          {:ok, tokens}
        else
          {:error,
           redirect_error(
             "invalid_scope",
             "scope contains an invalid token",
             redirect_uri,
             state
           )}
        end

      _ ->
        {:error, redirect_error("invalid_scope", "scope must be a string", redirect_uri, state)}
    end
  end

  # RFC 7636 §4.3 / RFC 9700: code_challenge is REQUIRED by default and
  # code_challenge_method must be "S256". A missing/malformed challenge or the
  # "plain" method is rejected as "invalid_request" (RFC 7636 §4.4.1, OAuth 2.0
  # Security BCP); "plain" is matched explicitly so the host can see the
  # downgrade attempt.
  #
  # When the caller relaxes the requirement (`require_pkce: false`, only ever
  # for a confidential client - public clients MUST use PKCE per RFC 9700
  # §2.1.1), a wholly absent `code_challenge` is permitted and the request
  # carries none (`{:ok, nil, nil}`). A challenge that IS present is still fully
  # enforced regardless of the flag: presence implies the client opted into
  # PKCE, so a downgrade or non-S256 method is always rejected.
  defp validate_pkce(params, require_pkce, redirect_uri, state) do
    challenge = Map.get(params, "code_challenge")
    method = Map.get(params, "code_challenge_method")

    cond do
      is_nil(challenge) and not require_pkce ->
        {:ok, nil, nil}

      not PKCE.valid_challenge?(challenge) ->
        {:error,
         redirect_error(
           "invalid_request",
           "a valid S256 code_challenge is required",
           redirect_uri,
           state
         )}

      method == @plain_method ->
        {:error,
         redirect_error(
           "invalid_request",
           "code_challenge_method=plain is not supported; use S256",
           redirect_uri,
           state
         )}

      method != PKCE.method() ->
        {:error,
         redirect_error(
           "invalid_request",
           "code_challenge_method=S256 is required",
           redirect_uri,
           state
         )}

      true ->
        {:ok, challenge, method}
    end
  end

  # OIDC Core §3.1.2.1: max_age is OPTIONAL and, when present, a non-negative
  # integer number of seconds. A non-integer or negative value is
  # "invalid_request".
  defp validate_max_age(params, redirect_uri, state) do
    case Map.get(params, "max_age") do
      nil ->
        {:ok, nil}

      value when is_integer(value) and value >= 0 ->
        {:ok, value}

      value when is_binary(value) ->
        case Integer.parse(value) do
          {seconds, ""} when seconds >= 0 -> {:ok, seconds}
          _ -> {:error, invalid_max_age(redirect_uri, state)}
        end

      _ ->
        {:error, invalid_max_age(redirect_uri, state)}
    end
  end

  defp invalid_max_age(redirect_uri, state) do
    redirect_error(
      "invalid_request",
      "max_age must be a non-negative integer",
      redirect_uri,
      state
    )
  end

  # OIDC Core §3.1.2.1: prompt is OPTIONAL and a space-delimited list whose
  # values are drawn from the fixed set {none, login, consent, select_account}.
  # An unknown token is "invalid_request" (OIDC Core §3.1.2.1). The parsed list
  # is exposed for the controller, which enforces semantics such as prompt=none
  # (the OP MUST NOT show UI); this module does not act on the values.
  defp validate_prompt(params, redirect_uri, state) do
    tokens = parse_space_list(Map.get(params, "prompt"))

    if Enum.all?(tokens, &(&1 in @prompt_values)) do
      {:ok, tokens}
    else
      {:error,
       redirect_error(
         "invalid_request",
         "prompt contains an unknown value",
         redirect_uri,
         state
       )}
    end
  end

  # OIDC Core §5.5: `claims` is OPTIONAL and, when present, is a JSON object.
  # The engine treats it as opaque request context and leaves claim-release
  # policy to the host/UserInfo layer; malformed JSON or a non-object value is
  # a redirectable invalid_request.
  defp validate_claims(params, redirect_uri, state) do
    case Map.get(params, "claims") do
      nil ->
        {:ok, %{}}

      value when is_binary(value) ->
        case JSON.decode(value) do
          {:ok, claims} when is_map(claims) ->
            {:ok, claims}

          _ ->
            {:error, redirect_error("invalid_request", "claims must be a JSON object", redirect_uri, state)}
        end

      _ ->
        {:error, redirect_error("invalid_request", "claims must be a JSON object", redirect_uri, state)}
    end
  end

  # OIDC Core §3.1.2.1: nonce is OPTIONAL for the code flow (RFC 6749 stays at
  # SHOULD), but REQUIRED when the OP policy demands it. The caller signals that
  # policy via require_nonce; a missing nonce under that policy is the
  # redirectable "invalid_request" error (OIDC Core §3.1.2.1).
  defp validate_nonce(params, require_nonce, redirect_uri, state) do
    case {string_or_nil(Map.get(params, "nonce")), require_nonce} do
      {nil, true} ->
        {:error,
         redirect_error(
           "invalid_request",
           "nonce is required",
           redirect_uri,
           state
         )}

      {nonce, _} ->
        {:ok, nonce}
    end
  end

  defp redirect_error(code, description, redirect_uri, state) do
    {:redirect,
     %{
       error: code,
       error_description: description,
       redirect_uri: redirect_uri,
       state: state
     }}
  end

  # OIDC Core §3.1.2.1 defines prompt and acr_values as space-delimited lists.
  defp parse_space_list(value) when is_binary(value), do: String.split(value, " ", trim: true)
  defp parse_space_list(_), do: []

  defp present?(value) when is_binary(value) and value != "", do: true
  defp present?(_), do: false

  defp string_or_nil(value) when is_binary(value) and value != "", do: value
  defp string_or_nil(_), do: nil
end
