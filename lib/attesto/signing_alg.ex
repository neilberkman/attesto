defmodule Attesto.SigningAlg do
  @moduledoc """
  Key-derived JOSE signing algorithm helpers.

  Attesto treats the algorithm as metadata of the trusted key selected by
  `kid`, never as policy learned from the presented token. RSA keys infer
  RS256 (RSASSA-PKCS1-v1_5) as the JWA default for the `RSA` key type, while
  EC/OKP keys infer their JOSE algorithm from the public JWK curve. RSA
  deployments that intentionally use PS256 can label the key through the
  keystore's alg metadata.
  """

  alias Attesto.Key

  @type alg :: String.t()

  @allowed ~w(RS256 PS256 ES256 ES384 ES512 EdDSA)

  @doc "Algorithms Attesto can sign/verify when backed by a matching key."
  @spec allowed() :: [alg()]
  def allowed, do: @allowed

  @fapi_algs ~w(PS256 ES256 EdDSA)

  @doc """
  Signing algorithms permitted for FAPI 2 client authentication and request
  objects: PS256, ES256, EdDSA.

  RS256 (RSASSA-PKCS1-v1_5) is deliberately excluded - FAPI 2 mandates PS256
  for RSA keys. This is the policy gate for verifying a signature a *client*
  presents; it is narrower than `allowed/0`, which still admits RS256 for the
  provider's own token signing.
  """
  @spec fapi_algs() :: [alg()]
  def fapi_algs, do: @fapi_algs

  @doc """
  Default set of algorithms accepted for signatures a *client* presents
  (client assertions and request objects).

  Equal to `fapi_algs/0`: PS256, ES256, EdDSA. A host with a non-FAPI profile
  can widen this by passing an explicit `:accepted_algs` opt to the relevant
  verifier; the default keeps the FAPI 2 gate.
  """
  @spec default_client_algs() :: [alg()]
  def default_client_algs, do: @fapi_algs

  @doc """
  Resolve the algorithm for a key in `keystore`.

  Resolution order:

    * per-key metadata from `key_algs/0`, keyed by RFC 7638 `kid`
    * `signing_alg/0` for the current signing key only
    * inference from the JWK type/curve
  """
  @spec for_key(module(), String.t(), keyword()) :: alg()
  def for_key(keystore, pem, opts \\ []) when is_atom(keystore) and is_binary(pem) do
    kid = Key.kid(pem)

    alg =
      key_algs(keystore)
      |> Map.get(kid)
      |> fallback_signing_alg(keystore, opts)
      |> fallback_inferred_alg(Key.jwk(pem))

    validate!(alg)
  end

  @doc "Infer the default algorithm from a parsed JWK's public members."
  @spec infer(JOSE.JWK.t()) :: alg()
  def infer(%JOSE.JWK{} = jwk) do
    jwk
    |> public_fields()
    |> infer_from_fields()
  end

  @doc "Return the digest algorithm used by an ID Token hash claim."
  @spec hash_alg(alg()) :: :sha256 | :sha384 | :sha512
  def hash_alg(alg) do
    case validate!(alg) do
      alg when alg in ~w(RS256 PS256 ES256 EdDSA) -> :sha256
      "ES384" -> :sha384
      "ES512" -> :sha512
    end
  end

  @doc "Return the number of left-most bytes used for OIDC hash claims."
  @spec hash_half_bytes(alg()) :: pos_integer()
  def hash_half_bytes(alg) do
    case hash_alg(alg) do
      :sha256 -> 16
      :sha384 -> 24
      :sha512 -> 32
    end
  end

  @doc "Validate that `alg` is one of Attesto's supported asymmetric JOSE algorithms."
  @spec validate!(term()) :: alg()
  def validate!(alg) when alg in @allowed, do: alg

  def validate!(alg) do
    raise ArgumentError,
          "unsupported signing algorithm #{inspect(alg)}; expected one of #{Enum.join(@allowed, ", ")}"
  end

  defp key_algs(keystore) do
    if exports?(keystore, :key_algs, 0) do
      keystore.key_algs()
      |> Map.new(fn {kid, alg} -> {to_string(kid), alg} end)
    else
      %{}
    end
  end

  defp fallback_signing_alg(nil, keystore, opts) do
    if Keyword.get(opts, :signing?) && exports?(keystore, :signing_alg, 0),
      do: keystore.signing_alg()
  end

  defp fallback_signing_alg(alg, _keystore, _opts), do: alg

  defp exports?(module, function, arity) do
    case Code.ensure_loaded(module) do
      {:module, ^module} -> function_exported?(module, function, arity)
      {:error, _reason} -> false
    end
  end

  defp fallback_inferred_alg(nil, jwk), do: infer(jwk)
  defp fallback_inferred_alg(alg, _jwk), do: alg

  defp public_fields(jwk) do
    jwk
    |> JOSE.JWK.to_public_map()
    |> elem(1)
  end

  defp infer_from_fields(%{"kty" => "RSA"}), do: "RS256"
  defp infer_from_fields(%{"kty" => "EC", "crv" => "P-256"}), do: "ES256"
  defp infer_from_fields(%{"kty" => "EC", "crv" => "P-384"}), do: "ES384"
  defp infer_from_fields(%{"kty" => "EC", "crv" => "P-521"}), do: "ES512"
  defp infer_from_fields(%{"kty" => "OKP", "crv" => crv}) when crv in ["Ed25519", "Ed448"], do: "EdDSA"

  defp infer_from_fields(%{"kty" => kty} = fields) do
    raise ArgumentError,
          "unsupported signing key type #{inspect(kty)}#{curve_suffix(fields)}; expected RSA, EC P-256/P-384/P-521, or OKP Ed25519/Ed448"
  end

  defp infer_from_fields(_fields) do
    raise ArgumentError, "unsupported signing key; missing JWK kty"
  end

  defp curve_suffix(%{"crv" => crv}), do: " curve #{inspect(crv)}"
  defp curve_suffix(_), do: ""
end
