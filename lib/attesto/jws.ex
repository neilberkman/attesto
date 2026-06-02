defmodule Attesto.JWS do
  @moduledoc false

  alias Attesto.Key
  alias Attesto.SigningAlg

  @doc false
  @spec sign_compact(String.t(), map(), map()) :: String.t()
  def sign_compact(pem, header, claims) when is_binary(pem) and is_map(header) and is_map(claims) do
    alg = header |> Map.fetch!("alg") |> SigningAlg.validate!()
    payload = JSON.encode!(claims)

    case alg do
      "PS" <> _ -> sign_ps_compact(pem, header, payload, alg)
      _ -> sign_jose_compact(pem, header, payload)
    end
  end

  defp sign_jose_compact(pem, header, payload) do
    signed =
      pem
      |> Key.signing_jwk()
      |> JOSE.JWS.sign(payload, header)

    {_protected_header, compact} = JOSE.JWS.compact(signed)
    compact
  end

  # RFC 7518 §3.5: RSASSA-PSS salt length MUST equal the hash output length.
  # JOSE 1.11 signs PS* with OpenSSL's maximum salt length, which it can verify
  # itself but strict FAPI/OIDF validators correctly reject.
  defp sign_ps_compact(pem, header, payload, alg) do
    encoded_header = encode_segment(header)
    encoded_payload = Base.url_encode64(payload, padding: false)
    signing_input = encoded_header <> "." <> encoded_payload

    signature =
      :public_key.sign(
        signing_input,
        hash_alg(alg),
        private_key(pem),
        pss_opts(alg)
      )

    signing_input <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp encode_segment(value) do
    value
    |> JSON.encode!()
    |> Base.url_encode64(padding: false)
  end

  defp private_key(pem) do
    pem
    |> :public_key.pem_decode()
    |> List.first()
    |> :public_key.pem_entry_decode()
  end

  defp pss_opts(alg) do
    [
      {:rsa_padding, :rsa_pkcs1_pss_padding},
      {:rsa_pss_saltlen, salt_length(alg)}
    ]
  end

  defp hash_alg("PS256"), do: :sha256
  defp hash_alg("PS384"), do: :sha384
  defp hash_alg("PS512"), do: :sha512

  defp salt_length("PS256"), do: 32
  defp salt_length("PS384"), do: 48
  defp salt_length("PS512"), do: 64
end
