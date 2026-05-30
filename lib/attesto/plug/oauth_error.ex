if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.OAuthError do
    @moduledoc """
    Render the RFC 6750 / RFC 9449 error responses for the Attesto plugs.

    Translates the verifier's error atoms into the wire responses a
    protected resource owes a client:

      * `invalid_token` (RFC 6750 §3.1) - 401 with a `WWW-Authenticate`
        challenge for the scheme the request used (`Bearer` or `DPoP`).
      * `invalid_dpop_proof` (RFC 9449 §7.1) - 401 with a `DPoP`
        challenge, for a DPoP proof that failed verification.
      * `use_dpop_nonce` (RFC 9449 §8) - 401 with a `DPoP` challenge and a
        fresh `DPoP-Nonce` header, telling the client to retry with the
        nonce.
      * `insufficient_scope` (RFC 6750 §3.1) - 403 naming the required
        scope.

    Each helper sets the status, the `WWW-Authenticate` header (and
    `DPoP-Nonce` when relevant), writes a small JSON body, and halts the
    pipeline. This module is part of the optional `Attesto.Plug` layer; it
    only compiles when `Plug` is available.
    """

    import Plug.Conn

    @type scheme :: :bearer | :dpop

    @doc """
    Respond 401 with a `WWW-Authenticate` challenge for `scheme` carrying
    `error` (an OAuth error code string). Options: `:description`
    (`error_description`) and `:dpop_nonce` (sets the `DPoP-Nonce` header,
    for `use_dpop_nonce`). Halts.
    """
    @spec unauthorized(Plug.Conn.t(), scheme(), String.t(), keyword()) :: Plug.Conn.t()
    def unauthorized(conn, scheme, error, opts \\ []) do
      params = [{"error", error} | description_param(opts)]

      conn
      |> maybe_put_dpop_nonce(Keyword.get(opts, :dpop_nonce))
      |> put_resp_header("www-authenticate", challenge(scheme, params))
      |> send_error(401, error, opts)
    end

    @doc """
    Respond 403 `insufficient_scope` naming the `required` scope list
    (RFC 6750 §3.1). Halts.
    """
    @spec insufficient_scope(Plug.Conn.t(), [String.t()], scheme()) :: Plug.Conn.t()
    def insufficient_scope(conn, required, scheme \\ :bearer) do
      scope = Enum.join(required, " ")

      params = [
        {"error", "insufficient_scope"},
        {"error_description", "requires scope: #{scope}"},
        {"scope", scope}
      ]

      conn
      |> put_resp_header("www-authenticate", challenge(scheme, params))
      |> send_error(403, "insufficient_scope", description: "requires scope: #{scope}")
    end

    # ----- internal -----

    defp challenge(scheme, params) do
      scheme_label =
        case scheme do
          :dpop -> "DPoP"
          _ -> "Bearer"
        end

      param_str = Enum.map_join(params, ", ", fn {k, v} -> ~s(#{k}="#{escape(v)}") end)
      scheme_label <> " " <> param_str
    end

    defp description_param(opts) do
      case Keyword.get(opts, :description) do
        nil -> []
        desc -> [{"error_description", desc}]
      end
    end

    defp maybe_put_dpop_nonce(conn, nil), do: conn
    defp maybe_put_dpop_nonce(conn, nonce), do: put_resp_header(conn, "dpop-nonce", nonce)

    defp send_error(conn, status, error, opts) do
      body =
        %{"error" => error}
        |> maybe_put("error_description", Keyword.get(opts, :description))
        |> JSON.encode!()

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, body)
      |> halt()
    end

    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)

    # `WWW-Authenticate` auth-param values are quoted-strings; escape the
    # two characters that would break out of the quotes.
    defp escape(value) do
      value
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
    end
  end
end
