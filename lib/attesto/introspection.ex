defmodule Attesto.Introspection do
  @moduledoc """
  OAuth 2.0 Token Introspection (RFC 7662), conn-free core.

  Given a presented token, decide whether it is currently active and, if so,
  describe it with the RFC 7662 response members. This is the deliberate
  introspection entry point; the transport layer authenticates the caller and
  decides (by content negotiation) whether to return the plain JSON response or
  a signed JWT (`Attesto.SignedIntrospection`, RFC 9701 / FAPI 2.0 Message
  Signing §5.5). Nothing here touches a `conn`.

  ## What "active" means (RFC 7662 §2.2)

    * **Access tokens** are stateless JWTs: a token is active iff it passes the
      full access-token verification (`Attesto.Token.verify/3` - signature,
      issuer, audience, temporal, required claims, principal, and `typ ==
      "access"`), the same checks a resource server applies. The ONE check
      skipped is the sender-constraint **binding** (the proof-key match): the
      `cnf` is part of who may *use* the token, verified when it is presented,
      and the introspecting caller holds no proof key - so introspection passes
      `require_confirmation_binding: false`. The `cnf` *shape* is still
      validated, and the binding is echoed in the response so a resource server
      can check it (RFC 7662 / RFC 8705 §3.2 / RFC 9449).

    * **Refresh tokens** are opaque, stored secrets whose context is host-owned
      and opaque to the core, so a refresh token present in the store,
      unconsumed, and unexpired is reported active with the minimal `active`
      member (plus `exp`); a consumed (rotated) or expired one is inactive, and
      its scope/subject are not decoded here.

    * Anything else - a malformed token, a forged signature, an expired token,
      or one absent from the store - is reported inactive (`%{"active" => false}`),
      never an error: RFC 7662 §2.2 forbids a token-existence oracle.

  `token_type_hint` (RFC 7662 §2.1) only reorders which check is tried first; an
  unmatched hint still falls through to the other.
  """

  alias Attesto.{Config, Secret, Token}

  @inactive %{"active" => false}

  # RFC 7662 §2.2 token_type values for the response.
  @bearer "Bearer"
  @dpop "DPoP"

  @type response :: %{required(String.t()) => term()}

  @type opts :: [
          refresh_store: module() | nil,
          token_type_hint: String.t() | nil,
          now: integer() | DateTime.t()
        ]

  @doc """
  Introspect `token`, returning the RFC 7662 response map (always `active`,
  plus the token's members when active). Never returns an error.

  Options:

    * `:refresh_store` - an `Attesto.RefreshStore` module to consult for opaque
      refresh tokens; when absent, only access tokens are introspected.
    * `:token_type_hint` - `"access_token"` or `"refresh_token"` (RFC 7662
      §2.1); reorders the attempts, never restricts them.
    * `:now` - the reference time (Unix seconds or `DateTime`), for tests.
  """
  @spec introspect(Config.t(), String.t(), opts()) :: response()
  def introspect(%Config{} = config, token, opts \\ []) when is_binary(token) and is_list(opts) do
    opts
    |> ordered_attempts()
    |> Enum.find_value(@inactive, fn attempt -> attempt.(config, token, opts) end)
  end

  # RFC 7662 §2.1: the hint is an optimisation, not a constraint - try the hinted
  # type first, then fall through to the other.
  defp ordered_attempts(opts) do
    attempts = [&access_token_response/3, &refresh_token_response/3]

    case Keyword.get(opts, :token_type_hint) do
      "refresh_token" -> Enum.reverse(attempts)
      _ -> attempts
    end
  end

  # An access token is active iff it passes the full access-token verification
  # (signature, issuer, audience, temporal, required claims, principal, and
  # typ == "access") - the SAME checks the resource-server path applies, so a
  # wrong-audience, non-access, or otherwise invalid token is inactive. Only the
  # sender-binding proof match is skipped (the caller is not the token's
  # presenter and holds no proof key); the `cnf` shape is still validated and
  # the binding is echoed in the response for the resource server to check.
  defp access_token_response(%Config{} = config, token, opts) do
    case Token.verify(config, token, verify_opts(opts)) do
      {:ok, claims} -> rfc7662_response(claims)
      {:error, _reason} -> nil
    end
  end

  defp verify_opts(opts) do
    base = [expected_typ: "access", require_confirmation_binding: false]

    case Keyword.fetch(opts, :now) do
      {:ok, now} -> [{:now, now} | base]
      :error -> base
    end
  end

  defp refresh_token_response(_config, token, opts) do
    with store when is_atom(store) and not is_nil(store) <- Keyword.get(opts, :refresh_store),
         {:ok, entry} <- store.get(Secret.hash(token)),
         true <- active_refresh?(entry, now(opts)) do
      %{"active" => true, "exp" => entry.expires_at}
    else
      _ -> nil
    end
  end

  # A refresh token is active only while it is explicitly unconsumed and
  # unexpired. Fail closed: an entry must carry `consumed: false` and an integer
  # `expires_at` in the future to be active, so a consumed (rotated) token - or
  # a malformed record missing `:consumed` - introspects as inactive.
  defp active_refresh?(%{consumed: false, expires_at: exp}, now) when is_integer(exp), do: exp > now
  defp active_refresh?(_entry, _now), do: false

  # Map the verified access-token claims onto the RFC 7662 response members,
  # carrying through only the members that are present. token_type reflects the
  # sender-constraint: a DPoP-bound token (cnf.jkt) is "DPoP", otherwise
  # "Bearer". The `cnf` is echoed so a resource server can verify the binding.
  defp rfc7662_response(claims) do
    %{"active" => true}
    |> copy(claims, "scope")
    |> copy(claims, "client_id")
    |> copy(claims, "sub")
    |> copy(claims, "aud")
    |> copy(claims, "iss")
    |> copy(claims, "exp")
    |> copy(claims, "iat")
    |> copy(claims, "jti")
    |> copy(claims, "cnf")
    |> Map.put("token_type", token_type(claims))
  end

  defp token_type(claims) do
    if is_binary(get_in(claims, ["cnf", "jkt"])), do: @dpop, else: @bearer
  end

  defp copy(response, claims, key) do
    case Map.get(claims, key) do
      nil -> response
      value -> Map.put(response, key, value)
    end
  end

  defp now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end
end
