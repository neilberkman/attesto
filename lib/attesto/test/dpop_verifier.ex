defmodule Attesto.Test.DPoPVerifier do
  @moduledoc """
  Server-side DPoP verification harness for host application test suites.

  Where `Attesto.Test.DPoP` builds the *client* half of an RFC 9449 exchange -
  a sender-constrained access token, the matching proof, and deliberately
  broken proofs - this module exercises the *server* half from a plain request
  description (method, URL, headers) and returns a test-friendly result.

  It does NOT reimplement RFC 9449. It is a thin adapter that delegates every
  security decision to Attesto's production verifiers:

    * the DPoP proof is checked by `Attesto.DPoP.verify_proof/2`;
    * when token verification is requested, the access token is checked by
      `Attesto.Token.verify/3`, including the RFC 7800 `cnf.jkt` sender
      constraint that binds the token to the proof key.

  Because it calls the same functions the resource server runs in production, a
  passing assertion here means the proof or token would pass the real resource
  server, and it tracks the verifier automatically when a rule changes.

  It depends on neither Plug, Phoenix, nor any HTTP client: a request is an
  ordinary keyword list and a failure is an ordinary map, so it runs from any
  ExUnit suite. The failure map mirrors the wire response a DPoP-aware resource
  server owes the client (RFC 6750 §3.1 / RFC 9449 §7.1, §8) - the HTTP status,
  the `WWW-Authenticate` challenge, and an optional `DPoP-Nonce` - so a test can
  assert on the protocol-visible challenge without standing up a connection.

  ## Request options

    * `:method` (or `:http_method`) - the HTTP method, e.g. `"GET"`. Required.
    * `:url` (or `:http_uri`) - the request target URI, scheme and host
      included; query/fragment are normalized away by the verifier. Required.
    * `:headers` - a list of `{name, value}` pairs or a map; names are matched
      case-insensitively. The `authorization` and `dpop` headers are read.
    * `:access_token` - the access token the proof's `ath` must bind to and the
      token to verify. Defaults to the token carried in the `Authorization`
      header. Omit it (and the header) for a proof-only / token-endpoint proof,
      where no access token exists yet and `ath` is not constrained.
    * `:verify_token` - when `true`, the access token is verified with
      `Attesto.Token.verify/3` and `:config` is required. Default `false`.
    * `:config` - an `Attesto.Config` or a zero-arity function returning one.
      Required when `:verify_token` is `true`.
    * `:replay_check` - the RFC 9449 §11.1 `(jti, ttl) -> :ok | {:error,
      :replay}` callback, forwarded to `Attesto.DPoP.verify_proof/2`.
    * `:nonce_check` - the RFC 9449 §8 `(nonce | nil) -> :ok | {:error,
      :use_dpop_nonce}` callback, forwarded to `Attesto.DPoP.verify_proof/2`.
    * `:nonce_issue` - a zero-arity function returning a fresh nonce. When a
      `use_dpop_nonce` challenge is produced, its value is placed on the
      challenge's `DPoP-Nonce` header (mirroring a resource server's reply).
    * `:now` - clock override (`DateTime` or unix seconds), forwarded to both
      verifiers.
    * `:max_age_seconds` - proof acceptance window, forwarded to the proof
      verifier.
    * `:expected_typ`, `:mtls_cert_thumbprint` - forwarded to
      `Attesto.Token.verify/3` when token verification runs.

  ## Result

    * `{:ok, verified}` where `verified` is a map with `:scheme`
      (`:dpop | :bearer`), `:jkt` (the verified proof thumbprint, or `nil`),
      `:proof` (the `Attesto.DPoP.verify_proof/2` result, or `nil`), and
      `:claims` (the verified token claims, or `nil` when token verification was
      not requested).
    * `{:error, challenge}` where `challenge` is a map with `:status`,
      `:error` (the OAuth error code string), `:error_reason` (the underlying
      verifier atom), `:error_description`, `:scheme`, `:www_authenticate` (the
      challenge string), `:dpop_nonce` (or `nil`), and `:headers` (a list of
      `{name, value}` pairs including `WWW-Authenticate`).

  ## Example

      jwk = Attesto.Test.DPoP.generate_key()

      {token, _resp} =
        Attesto.Test.DPoP.mint_access_token(config, %{
          kind: "client",
          sub: "oc_acme",
          scopes: ["read"],
          claims: %{"client_id" => "acme"}
        }, jwk)

      url = "https://api.example.test/resource"
      proof = Attesto.Test.DPoP.proof(jwk, "GET", url, access_token: token)

      {:ok, verified} =
        Attesto.Test.DPoPVerifier.verify_request(
          config: config,
          method: "GET",
          url: url,
          headers: [
            {"authorization", "DPoP " <> token},
            {"dpop", proof}
          ],
          verify_token: true
        )

      verified.claims["sub"]
      # => "oc_acme"
  """

  alias Attesto.Config
  alias Attesto.DPoP
  alias Attesto.Token

  @type scheme :: :bearer | :dpop

  @type verified :: %{
          scheme: scheme(),
          jkt: String.t() | nil,
          proof: DPoP.verified_proof() | nil,
          claims: Token.claims() | nil
        }

  @type challenge :: %{
          status: pos_integer(),
          scheme: scheme(),
          error: String.t(),
          error_reason: atom(),
          error_description: String.t() | nil,
          www_authenticate: String.t(),
          dpop_nonce: String.t() | nil,
          headers: [{String.t(), String.t()}]
        }

  @doc """
  Verify a protected-resource (or token-endpoint) request described by `opts`.

  See the module documentation for the accepted options and the shape of the
  `{:ok, verified}` / `{:error, challenge}` result. Raises `ArgumentError` when
  `:method`/`:url` are missing, or when `:verify_token` is `true` without a
  `:config`.
  """
  @spec verify_request(keyword()) :: {:ok, verified()} | {:error, challenge()}
  def verify_request(opts) when is_list(opts) do
    method = require_string!(opts, [:method, :http_method])
    url = require_string!(opts, [:url, :http_uri])
    headers = Keyword.get(opts, :headers, [])

    {scheme, header_token} = credential(headers)
    proof = header(headers, "dpop")
    token = Keyword.get(opts, :access_token) || header_token

    dispatch(scheme, proof, token, method, url, opts)
  end

  # ----- scheme dispatch -----

  defp dispatch(:malformed, _proof, _token, _method, _url, _opts) do
    {:error, challenge(:bearer, "invalid_token", "malformed Authorization header", :malformed_authorization)}
  end

  defp dispatch(:none, proof, token, method, url, opts) do
    without_authorization(proof, token, method, url, opts)
  end

  defp dispatch(:bearer, proof, token, _method, _url, opts) do
    with_bearer(proof, token, opts)
  end

  defp dispatch(:dpop, proof, token, method, url, opts) do
    with_dpop(proof, token, method, url, opts)
  end

  # RFC 9449 §7.1: a request that presents its token under `Bearer` while
  # carrying a `DPoP` header is mixing schemes; the proof is bound to nothing.
  # Steer the client to the DPoP scheme rather than honouring the header.
  defp with_bearer(nil, token, opts), do: verify_token_only(token, opts)

  defp with_bearer(_proof, _token, _opts) do
    {:error, challenge(:dpop, "invalid_dpop_proof", "dpop_scheme_required", :dpop_scheme_required)}
  end

  defp with_dpop(nil, _token, _method, _url, _opts) do
    {:error, challenge(:dpop, "invalid_dpop_proof", "missing_proof", :missing_proof)}
  end

  defp with_dpop(proof, token, method, url, opts) do
    verify_dpop_then_token(proof, token, method, url, opts)
  end

  # No `Authorization` header: a `DPoP` header alone is a token-endpoint /
  # proof-only request (no access token to bind unless one was passed
  # explicitly). A bare explicit token with no header is treated as a Bearer
  # credential. Neither is `:missing`.
  defp without_authorization(nil, nil, _method, _url, _opts) do
    {:error, challenge(:bearer, "invalid_token", "missing Authorization header", :missing_credential)}
  end

  defp without_authorization(nil, token, _method, _url, opts) do
    verify_token_only(token, opts)
  end

  defp without_authorization(proof, token, method, url, opts) do
    verify_dpop_then_token(proof, token, method, url, opts)
  end

  # ----- delegation to the production verifiers -----

  defp verify_dpop_then_token(proof, token, method, url, opts) do
    case DPoP.verify_proof(proof, proof_opts(method, url, token, opts)) do
      {:ok, %{jkt: jkt} = verified_proof} ->
        finish(:dpop, jkt, verified_proof, token, opts)

      {:error, :use_dpop_nonce} ->
        {:error, nonce_challenge(opts)}

      {:error, reason} ->
        {:error, challenge(:dpop, "invalid_dpop_proof", to_string(reason), reason)}
    end
  end

  defp finish(scheme, jkt, verified_proof, token, opts) do
    if verify_token?(opts) do
      case Token.verify(require_config!(opts), token, token_opts(jkt, opts)) do
        {:ok, claims} -> {:ok, verified(scheme, jkt, verified_proof, claims)}
        {:error, reason} -> {:error, token_challenge(scheme, reason)}
      end
    else
      {:ok, verified(scheme, jkt, verified_proof, nil)}
    end
  end

  defp verify_token_only(nil, _opts) do
    {:error, challenge(:bearer, "invalid_token", "missing credential", :missing_credential)}
  end

  defp verify_token_only(token, opts) do
    if verify_token?(opts) do
      # A DPoP-bound token presented this way carries no proof, so `dpop_jkt` is
      # nil and `Attesto.Token.verify/3` answers `:dpop_proof_required`, which
      # `token_challenge/2` surfaces as a DPoP challenge (RFC 9449 §7.1).
      case Token.verify(require_config!(opts), token, token_opts(nil, opts)) do
        {:ok, claims} -> {:ok, verified(:bearer, nil, nil, claims)}
        {:error, reason} -> {:error, token_challenge(:bearer, reason)}
      end
    else
      {:ok, verified(:bearer, nil, nil, nil)}
    end
  end

  # RFC 9449 §7.1: a token that is DPoP-bound but presented without a valid
  # proof yields `:dpop_proof_required`; the resource server answers with a
  # `DPoP` challenge so the client re-presents under the DPoP scheme.
  defp token_challenge(_scheme, :dpop_proof_required) do
    challenge(:dpop, "invalid_token", "dpop_proof_required", :dpop_proof_required)
  end

  defp token_challenge(scheme, reason) do
    challenge(scheme, "invalid_token", to_string(reason), reason)
  end

  defp verified(scheme, jkt, proof, claims) do
    %{scheme: scheme, jkt: jkt, proof: proof, claims: claims}
  end

  # ----- option assembly -----

  defp proof_opts(method, url, token, opts) do
    [http_method: method, http_uri: url]
    |> put_opt(:access_token, token)
    |> put_opt(:replay_check, Keyword.get(opts, :replay_check))
    |> put_opt(:nonce_check, Keyword.get(opts, :nonce_check))
    |> put_opt(:now, Keyword.get(opts, :now))
    |> put_opt(:max_age_seconds, Keyword.get(opts, :max_age_seconds))
  end

  # `:dpop_jkt` is included verbatim (even when nil): a nil thumbprint is how
  # `Attesto.Token.verify/3` learns no proof was presented, which is exactly
  # what must trip `:dpop_proof_required` for a DPoP-bound token.
  defp token_opts(jkt, opts) do
    [dpop_jkt: jkt]
    |> put_opt(:now, Keyword.get(opts, :now))
    |> put_opt(:expected_typ, Keyword.get(opts, :expected_typ))
    |> put_opt(:mtls_cert_thumbprint, Keyword.get(opts, :mtls_cert_thumbprint))
  end

  defp verify_token?(opts), do: Keyword.get(opts, :verify_token, false) == true

  # ----- challenge construction (mirrors Attesto.Plug.OAuthError, Plug-free) -----

  defp challenge(scheme, error, description, reason) do
    params = [{"error", error} | description_param(description)]
    www = www_authenticate(scheme, params)

    %{
      status: 401,
      scheme: scheme,
      error: error,
      error_reason: reason,
      error_description: description,
      www_authenticate: www,
      dpop_nonce: nil,
      headers: [
        {"www-authenticate", www},
        {"cache-control", "no-store"},
        {"pragma", "no-cache"}
      ]
    }
  end

  defp nonce_challenge(opts) do
    base = challenge(:dpop, "use_dpop_nonce", nil, :use_dpop_nonce)

    case issue_nonce(opts) do
      nil -> base
      nonce -> %{base | dpop_nonce: nonce, headers: [{"dpop-nonce", nonce} | base.headers]}
    end
  end

  defp issue_nonce(opts) do
    case Keyword.get(opts, :nonce_issue) do
      fun when is_function(fun, 0) -> fun.()
      _ -> nil
    end
  end

  defp description_param(nil), do: []
  defp description_param(description), do: [{"error_description", description}]

  defp www_authenticate(scheme, params) do
    label =
      case scheme do
        :dpop -> "DPoP"
        _ -> "Bearer"
      end

    param_str = Enum.map_join(params, ", ", fn {k, v} -> ~s(#{k}="#{escape(v)}") end)
    label <> " " <> param_str
  end

  # `WWW-Authenticate` auth-param values are quoted-strings; escape the two
  # characters that would otherwise break out of the quotes.
  defp escape(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end

  # ----- request parsing -----

  defp credential(headers) do
    case header(headers, "authorization") do
      nil -> {:none, nil}
      value -> parse_authorization(value)
    end
  end

  defp parse_authorization(value) do
    case String.split(value, " ", parts: 2) do
      [scheme, token] -> {scheme_atom(String.downcase(scheme)), String.trim(token)}
      _ -> {:malformed, nil}
    end
  end

  defp scheme_atom("bearer"), do: :bearer
  defp scheme_atom("dpop"), do: :dpop
  defp scheme_atom(_other), do: :malformed

  defp header(headers, name) when is_list(headers) or is_map(headers) do
    wanted = String.downcase(name)

    Enum.find_value(headers, fn {key, value} ->
      if String.downcase(to_string(key)) == wanted, do: value
    end)
  end

  # ----- option validation -----

  defp require_string!(opts, keys) do
    value =
      Enum.find_value(keys, fn key ->
        case Keyword.get(opts, key) do
          v when is_binary(v) and v != "" -> v
          _ -> nil
        end
      end)

    value ||
      raise ArgumentError,
            "Attesto.Test.DPoPVerifier.verify_request/1 requires one of #{inspect(keys)} " <>
              "as a non-empty string"
  end

  defp require_config!(opts) do
    case Keyword.get(opts, :config) do
      %Config{} = config ->
        config

      fun when is_function(fun, 0) ->
        fun.()

      _ ->
        raise ArgumentError,
              "Attesto.Test.DPoPVerifier: verify_token: true requires a :config " <>
                "(an %Attesto.Config{} or a zero-arity function returning one)"
    end
  end

  defp put_opt(opts, _key, nil), do: opts
  defp put_opt(opts, key, value), do: Keyword.put(opts, key, value)
end
