defmodule Attesto.TokenAtJwtTest do
  @moduledoc false
  # RFC 9068 §2.1: an OAuth JWT access token SHOULD carry the JOSE header
  # `typ: "at+jwt"` so a resource server can tell it apart (by media type)
  # from an ID token or any other JWT. `Attesto.Token.mint/3` emits that
  # header for access tokens when `config.access_token_header_typ` is set
  # (default "at+jwt"); a refresh token carries none, and a host can set a
  # custom value or `nil`.
  #
  # Factory.config/2 installs the signing PEM into the global app env
  # (Attesto.Keystore.Static singleton), so these run serially.
  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Token

  setup do
    pem = Factory.rsa_pem()
    {:ok, pem: pem}
  end

  # The minted token's JOSE protected header. JOSE.JWS.peek_protected/1
  # returns the raw base64url-decoded protected-header JSON without
  # verifying the signature, which is exactly what we want to assert on.
  defp protected_header(jwt) when is_binary(jwt) do
    jwt
    |> JOSE.JWS.peek_protected()
    |> JSON.decode!()
  end

  defp client_principal do
    %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}}
  end

  describe "access-token JOSE header typ" do
    test "defaults to \"at+jwt\"", %{pem: pem} do
      config = Factory.config(pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      assert header["typ"] == "at+jwt"
    end

    test "alg is RS256 and kid is present on every access token", %{pem: pem} do
      config = Factory.config(pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
      assert header["kid"] != ""
    end

    test "a custom access_token_header_typ value appears verbatim", %{pem: pem} do
      config = Factory.config(pem, access_token_header_typ: "application/at+jwt")

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      assert header["typ"] == "application/at+jwt"
      # alg/kid are unaffected by the typ override.
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
    end

    test "access_token_header_typ: nil yields no \"typ\" header", %{pem: pem} do
      config = Factory.config(pem, access_token_header_typ: nil)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      refute Map.has_key?(header, "typ")
      # alg/kid are still present without a typ.
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
    end
  end

  describe "non-RSA signing key" do
    test "minting with an EC P-256 signing key uses ES256 and verifies" do
      ec_pem =
        {:ec, "P-256"}
        |> JOSE.JWK.generate_key()
        |> JOSE.JWK.to_pem()
        |> elem(1)

      config = Factory.config(ec_pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      assert header["alg"] == "ES256"
      assert header["kid"] == Attesto.Key.kid(ec_pem)
      assert {:ok, claims} = Token.verify(config, jwt)
      assert claims["sub"] == "oc_abc123"
    end
  end

  describe "refresh-token JOSE header typ" do
    test ~s(a token minted with typ: "refresh" carries no "typ" header), %{pem: pem} do
      # The header typ tags access tokens specifically (RFC 9068). A
      # refresh token is not an OAuth JWT access token, so it gets no
      # header typ even when access_token_header_typ is set.
      config = Factory.config(pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), typ: "refresh")

      header = protected_header(jwt)
      refute Map.has_key?(header, "typ")
      # alg/kid are always present, refresh included.
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
    end

    test "a custom access_token_header_typ does not leak onto a refresh token", %{pem: pem} do
      config = Factory.config(pem, access_token_header_typ: "application/at+jwt")

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), typ: "refresh")

      header = protected_header(jwt)
      refute Map.has_key?(header, "typ")
    end
  end
end
