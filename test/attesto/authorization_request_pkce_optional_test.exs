defmodule Attesto.AuthorizationRequestPKCEOptionalTest do
  @moduledoc """
  Tests for the `:require_pkce` option of `Attesto.AuthorizationRequest.validate/2`
  (RFC 7636 / RFC 9700). PKCE is required by default; a host may relax it for a
  confidential client. Even when relaxed, a `code_challenge` that is present is
  still fully enforced (S256, no `plain`).
  """
  use ExUnit.Case, async: true

  alias Attesto.AuthorizationRequest

  @registered ["https://client.example/cb"]

  defp params(overrides \\ %{}) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => "client-123",
        "redirect_uri" => "https://client.example/cb",
        "scope" => "openid"
      },
      overrides
    )
  end

  @valid_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  describe "PKCE required by default" do
    test "a request with no code_challenge is rejected by default" do
      assert {:error, {:redirect, error}} =
               AuthorizationRequest.validate(params(), registered_redirect_uris: @registered)

      assert error.error == "invalid_request"
    end

    test "a request with no code_challenge is rejected with require_pkce: true" do
      assert {:error, {:redirect, %{error: "invalid_request"}}} =
               AuthorizationRequest.validate(params(),
                 registered_redirect_uris: @registered,
                 require_pkce: true
               )
    end
  end

  describe "require_pkce: false (confidential-client relaxation)" do
    test "a request with no code_challenge is accepted and carries no challenge" do
      assert {:ok, request} =
               AuthorizationRequest.validate(params(),
                 registered_redirect_uris: @registered,
                 require_pkce: false
               )

      assert request.code_challenge == nil
      assert request.code_challenge_method == nil
      assert request.client_id == "client-123"
    end

    test "a present code_challenge is STILL fully enforced (S256 accepted)" do
      assert {:ok, request} =
               AuthorizationRequest.validate(
                 params(%{
                   "code_challenge" => @valid_challenge,
                   "code_challenge_method" => "S256"
                 }),
                 registered_redirect_uris: @registered,
                 require_pkce: false
               )

      assert request.code_challenge == @valid_challenge
      assert request.code_challenge_method == "S256"
    end

    test "a present code_challenge with method=plain is STILL rejected" do
      assert {:error, {:redirect, error}} =
               AuthorizationRequest.validate(
                 params(%{
                   "code_challenge" => @valid_challenge,
                   "code_challenge_method" => "plain"
                 }),
                 registered_redirect_uris: @registered,
                 require_pkce: false
               )

      assert error.error == "invalid_request"
      assert error.error_description =~ "plain"
    end

    test "a malformed present code_challenge is STILL rejected" do
      assert {:error, {:redirect, %{error: "invalid_request"}}} =
               AuthorizationRequest.validate(
                 params(%{"code_challenge" => "tooshort", "code_challenge_method" => "S256"}),
                 registered_redirect_uris: @registered,
                 require_pkce: false
               )
    end
  end
end
