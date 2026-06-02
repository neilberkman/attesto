defmodule Attesto.ClientAssertion do
  @moduledoc """
  `private_key_jwt` client authentication verification (RFC 7523 / OIDC Core).

  The host owns client registration and key storage. This module only verifies
  a compact client assertion against trusted client JWKs supplied by the host
  and checks the standard claims:

    * `iss` and `sub` equal the OAuth `client_id`
    * `aud` contains the expected token endpoint/audience
    * `exp` is in the future
    * `iat`, when present, is not meaningfully in the future
    * `jti` is present for replay tracking by the caller

  The JOSE algorithm is resolved from the trusted JWK's `alg` member when
  present, otherwise from the key shape. It is never accepted just because the
  presented JWT header names it.
  """

  alias Attesto.SigningAlg

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @clock_skew_seconds 60

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:max_lifetime, pos_integer()}
        ]

  @type verify_error ::
          :invalid_assertion
          | :invalid_signature
          | :invalid_client_id
          | :invalid_audience
          | :expired
          | :not_yet_valid
          | :missing_jti
          | :unsupported_critical_header

  @doc "The required `client_assertion_type` value for `private_key_jwt`."
  @spec assertion_type() :: String.t()
  def assertion_type, do: @assertion_type

  @doc "Peek `iss` from an assertion without trusting it."
  @spec peek_client_id(String.t()) :: {:ok, String.t()} | {:error, :invalid_assertion}
  def peek_client_id(assertion) when is_binary(assertion) do
    with :ok <- check_compact_form(assertion),
         {:ok, claims} <- peek_payload(assertion),
         iss when is_binary(iss) and iss != "" <- Map.get(claims, "iss") do
      {:ok, iss}
    else
      _ -> {:error, :invalid_assertion}
    end
  end

  def peek_client_id(_), do: {:error, :invalid_assertion}

  @doc """
  Verify a client assertion against the client's trusted JWK Set.

  `trusted_jwks` may be an RFC 7517 JWK Set (`%{"keys" => [...]}`), a single
  public JWK map, or a list of public JWK maps.
  """
  @spec verify(String.t(), String.t(), String.t() | [String.t()], map() | [map()] | map(), verify_opts()) ::
          {:ok, map()} | {:error, verify_error()}
  def verify(assertion, client_id, expected_audience, trusted_jwks, opts \\ [])

  def verify(assertion, client_id, expected_audience, trusted_jwks, opts)
      when is_binary(assertion) and is_binary(client_id) and is_list(opts) do
    with :ok <- check_compact_form(assertion),
         {:ok, header} <- peek_header(assertion),
         :ok <- check_crit(header),
         {:ok, claims} <- verify_signature(assertion, header, trusted_jwks),
         :ok <- check_client_id(claims, client_id),
         :ok <- check_audience(claims, expected_audience),
         :ok <- check_expiry(claims, opts),
         :ok <- check_iat(claims, opts),
         :ok <- check_jti(claims) do
      {:ok, claims}
    end
  end

  def verify(_assertion, _client_id, _expected_audience, _trusted_jwks, _opts), do: {:error, :invalid_assertion}

  defp verify_signature(assertion, header, trusted_jwks) do
    case candidates(trusted_jwks, Map.get(header, "kid")) do
      [] -> {:error, :invalid_signature}
      jwks -> verify_against_any(jwks, assertion)
    end
  end

  defp candidates(trusted_jwks, header_kid) do
    trusted_jwks
    |> normalize_jwks()
    |> Enum.map(fn jwk_map ->
      jwk = JOSE.JWK.from_map(jwk_map)
      alg = Map.get(jwk_map, "alg") || SigningAlg.infer(jwk)
      {Map.get(jwk_map, "kid"), SigningAlg.validate!(alg), jwk}
    end)
    |> Enum.filter(fn {_kid, alg, _jwk} -> alg in SigningAlg.fapi_algs() end)
    |> filter_by_kid(header_kid)
  rescue
    _ -> []
  end

  defp normalize_jwks(%{"keys" => keys}) when is_list(keys), do: keys
  defp normalize_jwks(keys) when is_list(keys), do: keys
  defp normalize_jwks(%{} = jwk), do: [jwk]
  defp normalize_jwks(_), do: []

  defp filter_by_kid(keyed, nil), do: keyed
  defp filter_by_kid(keyed, kid), do: Enum.filter(keyed, fn {k, _alg, _jwk} -> k == kid end)

  defp verify_against_any(candidates, assertion) do
    Enum.reduce_while(candidates, {:error, :invalid_signature}, fn {_kid, alg, jwk}, acc ->
      case JOSE.JWT.verify_strict(jwk, [alg], assertion) do
        {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:halt, {:ok, claims}}
        {false, _jwt, _jws} -> {:cont, acc}
        _other -> {:halt, {:error, :invalid_assertion}}
      end
    end)
  end

  defp check_client_id(%{"iss" => id, "sub" => id}, id), do: :ok
  defp check_client_id(_claims, _client_id), do: {:error, :invalid_client_id}

  defp check_audience(%{"aud" => aud}, expected) when is_list(expected) do
    if aud_intersects?(aud, expected), do: :ok, else: {:error, :invalid_audience}
  end

  defp check_audience(%{"aud" => aud}, expected) when is_binary(expected) do
    check_audience(%{"aud" => aud}, [expected])
  end

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  defp aud_intersects?(aud, expected) when is_binary(aud), do: aud in expected
  defp aud_intersects?(aud, expected) when is_list(aud), do: Enum.any?(aud, &(&1 in expected))
  defp aud_intersects?(_aud, _expected), do: false

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) and exp >= 0 do
    now = unix_now(opts)
    if exp > now, do: check_max_lifetime(exp, now, opts), else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: {:error, :expired}

  defp check_max_lifetime(exp, now, opts) do
    case Keyword.get(opts, :max_lifetime) do
      n when is_integer(n) and n > 0 and exp - now <= n -> :ok
      n when is_integer(n) and n > 0 -> {:error, :invalid_assertion}
      _ -> :ok
    end
  end

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    if iat <= unix_now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_iat(%{"iat" => _}, _opts), do: {:error, :not_yet_valid}
  defp check_iat(_claims, _opts), do: :ok

  defp check_jti(%{"jti" => jti}) when is_binary(jti) and jti != "", do: :ok
  defp check_jti(_claims), do: {:error, :missing_jti}

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = dt -> DateTime.to_unix(dt)
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end

  defp check_crit(header) do
    if Map.has_key?(header, "crit"), do: {:error, :unsupported_critical_header}, else: :ok
  end

  defp check_compact_form(jwt) do
    case String.split(jwt, ".") do
      [_, _, _] = segments ->
        if Enum.all?(segments, &canonical_base64url?/1),
          do: :ok,
          else: {:error, :invalid_assertion}

      _ ->
        {:error, :invalid_assertion}
    end
  end

  defp canonical_base64url?(segment) do
    case Base.url_decode64(segment, padding: false) do
      {:ok, decoded} -> Base.url_encode64(decoded, padding: false) == segment
      :error -> false
    end
  end

  defp peek_header(jwt), do: peek_segment(jwt, 0)
  defp peek_payload(jwt), do: peek_segment(jwt, 1)

  defp peek_segment(jwt, index) do
    with segment when is_binary(segment) <- Enum.at(String.split(jwt, "."), index),
         {:ok, decoded} <- Base.url_decode64(segment, padding: false),
         {:ok, %{} = map} <- JSON.decode(decoded) do
      {:ok, map}
    else
      _ -> {:error, :invalid_assertion}
    end
  rescue
    _ -> {:error, :invalid_assertion}
  end
end
