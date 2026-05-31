defmodule Attesto.AuthorizationCodePKCEOptionalTest do
  @moduledoc """
  Tests for issuing and redeeming an authorization code with NO PKCE challenge
  (the confidential-client relaxation, RFC 9700). A code issued without a
  challenge must be redeemable without a verifier; presenting a verifier against
  such an unbound code is an anomaly and fails closed.
  """
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.CodeStore.ETS

  setup do
    start_supervised!(ETS)
    %{store: ETS}
  end

  @base_attrs %{
    client_id: "client-123",
    redirect_uri: "https://client.example/cb",
    subject: "user-1"
  }

  describe "issue/3 without a code_challenge" do
    test "mints a code when no challenge is supplied", %{store: store} do
      assert {:ok, code} = AuthorizationCode.issue(store, @base_attrs)
      assert is_binary(code)
    end

    test "redeems without a verifier and returns the grant", %{store: store} do
      {:ok, code} = AuthorizationCode.issue(store, @base_attrs)

      assert {:ok, grant} =
               AuthorizationCode.redeem(store, code, %{
                 redirect_uri: "https://client.example/cb",
                 client_id: "client-123"
               })

      assert grant.subject == "user-1"
    end

    test "presenting a verifier against an unbound code fails closed", %{store: store} do
      {:ok, code} = AuthorizationCode.issue(store, @base_attrs)

      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(store, code, %{
                 redirect_uri: "https://client.example/cb",
                 client_id: "client-123",
                 code_verifier: "some-verifier-value-that-should-not-be-here-xx"
               })
    end
  end

  describe "issue/3 with a code_challenge still enforces PKCE" do
    @challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    @verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    test "a bound code requires the matching verifier", %{store: store} do
      {:ok, code} =
        AuthorizationCode.issue(store, Map.put(@base_attrs, :code_challenge, @challenge))

      # No verifier against a bound code -> fail.
      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(store, code, %{
                 redirect_uri: "https://client.example/cb",
                 client_id: "client-123"
               })
    end

    test "a bound code redeems with the correct verifier", %{store: store} do
      {:ok, code} =
        AuthorizationCode.issue(store, Map.put(@base_attrs, :code_challenge, @challenge))

      assert {:ok, grant} =
               AuthorizationCode.redeem(store, code, %{
                 redirect_uri: "https://client.example/cb",
                 client_id: "client-123",
                 code_verifier: @verifier
               })

      assert grant.subject == "user-1"
    end
  end
end
