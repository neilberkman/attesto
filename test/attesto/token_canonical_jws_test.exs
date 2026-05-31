defmodule Attesto.TokenCanonicalJWSTest do
  @moduledoc false
  # Regression for JWS signature malleability at the compact-form boundary
  # of Attesto.Token.verify/3.
  #
  # RFC 4648 §3.5: the 342-byte RS256 signature segment is a partial quantum
  # (342 rem 4 == 2), so its final base64url character carries four unused
  # low-order bits. Several distinct characters share the same significant
  # bits and therefore decode to the *same* signature bytes. Swapping the
  # trailing character for a same-decoding sibling yields a string that is
  # not byte-identical to the issuer's token but that JOSE's liberal decoder
  # normalises and verifies. An alphabet-only boundary check accepted it; the
  # canonical round-trip boundary (Base.url_decode64/encode64) rejects it as
  # :invalid_token before the token reaches JOSE.
  #
  # Factory.config/2 installs the signing PEM into the global
  # Attesto.Keystore.Static app env, so this runs serially.
  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Token

  @now 1_700_000_000

  setup do
    pem = Factory.rsa_pem()
    config = Factory.config(pem)

    principal = %{
      kind: "client",
      sub: "oc_canon",
      scopes: ["documents.read"],
      claims: %{"client_id" => "oc_canon"}
    }

    {:ok, %{access_token: jwt}} = Token.mint(config, principal, now: @now)
    # Sanity: the pristine token verifies.
    assert {:ok, _claims} = Token.verify(config, jwt, now: @now)

    {:ok, config: config, jwt: jwt}
  end

  describe "non-canonical compact form (Token.verify/3)" do
    test "rejects a non-canonical trailing signature character (malleability)", %{config: config, jwt: jwt} do
      mutated = swap_trailing_sibling(jwt)

      assert mutated != jwt
      assert {:error, :invalid_token} = Token.verify(config, mutated, now: @now)
    end

    test "rejects '=' padding appended to any compact segment", %{config: config, jwt: jwt} do
      segments = String.split(jwt, ".")

      for index <- 0..2 do
        padded =
          segments
          |> List.update_at(index, &(&1 <> "="))
          |> Enum.join(".")

        assert {:error, :invalid_token} = Token.verify(config, padded, now: @now),
               "expected padding in segment #{index} to be rejected"
      end
    end
  end

  # Replace the final base64url character of the signature segment with a
  # different character that decodes to the same bytes (RFC 4648 §3.5).
  defp swap_trailing_sibling(jwt) do
    [header, payload, sig] = String.split(jwt, ".")
    decoded = Base.url_decode64!(sig, padding: false)
    prefix = binary_part(sig, 0, byte_size(sig) - 1)
    last = :binary.at(sig, byte_size(sig) - 1)

    sibling =
      Enum.find(~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", fn c ->
        c != last and match?({:ok, ^decoded}, Base.url_decode64(prefix <> <<c>>, padding: false))
      end)

    Enum.join([header, payload, prefix <> <<sibling>>], ".")
  end
end
