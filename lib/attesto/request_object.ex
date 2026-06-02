defmodule Attesto.RequestObject do
  @moduledoc """
  Signed OpenID Connect Request Object verification (JAR, RFC 9101 / OIDC §6.1).

  This module verifies a compact JWT request object against trusted client
  JWKs supplied by the host. It deliberately rejects unsigned request objects:
  a host that wants request objects is opting into integrity protection, not a
  second unsigned parameter encoding.
  """

  alias Attesto.SigningAlg

  @clock_skew_seconds 60

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:issuer, String.t() | nil}
          | {:audience, String.t() | [String.t()]}
        ]

  @type verify_error ::
          :invalid_request_object
          | :request_not_supported
          | :invalid_signature
          | :invalid_issuer
          | :invalid_audience
          | :expired
          | :not_yet_valid
          | :unsupported_critical_header

  @doc """
  Verify and return a string-keyed parameter map from a signed request object.

  The object must carry `iss`, `client_id`, and `aud`. `iss` must match the
  object's `client_id` and the caller-supplied `:issuer`; `aud` must match the
  caller-supplied `:audience`.
  """
  @spec verify(String.t(), map() | [map()] | map(), verify_opts()) :: {:ok, map()} | {:error, verify_error()}
  def verify(jwt, trusted_jwks, opts \\ [])

  def verify(jwt, trusted_jwks, opts) when is_binary(jwt) and is_list(opts) do
    with :ok <- check_compact_form(jwt),
         {:ok, header} <- peek_header(jwt),
         :ok <- check_crit(header),
         :ok <- check_supported_alg(header),
         {:ok, claims} <- verify_signature(jwt, header, trusted_jwks),
         :ok <- check_claim_issuer(claims),
         :ok <- check_issuer(claims, Keyword.get(opts, :issuer)),
         :ok <- check_audience(claims, Keyword.get(opts, :audience)),
         :ok <- check_expiry(claims, opts),
         :ok <- check_iat(claims, opts) do
      {:ok, claims_to_params(claims)}
    end
  end

  def verify(_jwt, _trusted_jwks, _opts), do: {:error, :invalid_request_object}

  defp verify_signature(jwt, header, trusted_jwks) do
    case candidates(trusted_jwks, Map.get(header, "kid")) do
      [] -> {:error, :invalid_signature}
      jwks -> verify_against_any(jwks, jwt)
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

  defp verify_against_any(candidates, jwt) do
    Enum.reduce_while(candidates, {:error, :invalid_signature}, fn {_kid, alg, jwk}, acc ->
      case JOSE.JWT.verify_strict(jwk, [alg], jwt) do
        {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:halt, {:ok, claims}}
        {false, _jwt, _jws} -> {:cont, acc}
        _other -> {:halt, {:error, :invalid_request_object}}
      end
    end)
  end

  defp check_claim_issuer(%{"client_id" => client_id, "iss" => client_id})
       when is_binary(client_id) and client_id != "", do: :ok

  defp check_claim_issuer(_claims), do: {:error, :invalid_issuer}

  defp check_issuer(_claims, nil), do: {:error, :invalid_issuer}
  defp check_issuer(%{"iss" => iss}, iss), do: :ok
  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  defp check_audience(_claims, nil), do: {:error, :invalid_audience}

  defp check_audience(%{"aud" => aud}, expected) when is_list(expected) do
    if aud_intersects?(aud, expected), do: :ok, else: {:error, :invalid_audience}
  end

  defp check_audience(%{"aud" => aud}, expected) when is_binary(expected),
    do: check_audience(%{"aud" => aud}, [expected])

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  defp aud_intersects?(aud, expected) when is_binary(aud), do: aud in expected
  defp aud_intersects?(aud, expected) when is_list(aud), do: Enum.any?(aud, &(&1 in expected))
  defp aud_intersects?(_aud, _expected), do: false

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) and exp >= 0 do
    if exp > unix_now(opts), do: :ok, else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: :ok

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    if iat <= unix_now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_iat(%{"iat" => _}, _opts), do: {:error, :not_yet_valid}
  defp check_iat(_claims, _opts), do: :ok

  defp claims_to_params(claims) do
    claims
    |> Map.drop(~w(iss sub aud exp nbf iat jti))
    |> Enum.reduce(%{}, fn
      {key, value}, acc when is_binary(value) -> Map.put(acc, key, value)
      {key, value}, acc when is_boolean(value) or is_integer(value) -> Map.put(acc, key, to_string(value))
      {key, value}, acc when is_list(value) -> Map.put(acc, key, Enum.join(value, " "))
      {key, value}, acc when is_map(value) -> Map.put(acc, key, JSON.encode!(value))
      {_key, _value}, acc -> acc
    end)
  end

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

  defp check_supported_alg(%{"alg" => "none"}), do: {:error, :request_not_supported}
  defp check_supported_alg(_header), do: :ok

  defp check_compact_form(jwt) do
    case String.split(jwt, ".") do
      [_, _, _] = segments ->
        if Enum.all?(segments, &canonical_base64url?/1),
          do: :ok,
          else: {:error, :invalid_request_object}

      _ ->
        {:error, :invalid_request_object}
    end
  end

  defp canonical_base64url?(segment) do
    case Base.url_decode64(segment, padding: false) do
      {:ok, decoded} -> Base.url_encode64(decoded, padding: false) == segment
      :error -> false
    end
  end

  defp peek_header(jwt), do: peek_segment(jwt, 0)

  defp peek_segment(jwt, index) do
    with segment when is_binary(segment) <- Enum.at(String.split(jwt, "."), index),
         {:ok, decoded} <- Base.url_decode64(segment, padding: false),
         {:ok, %{} = map} <- JSON.decode(decoded) do
      {:ok, map}
    else
      _ -> {:error, :invalid_request_object}
    end
  rescue
    _ -> {:error, :invalid_request_object}
  end
end
