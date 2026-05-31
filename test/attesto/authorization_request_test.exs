defmodule Attesto.AuthorizationRequestTest do
  use ExUnit.Case, async: true

  alias Attesto.AuthorizationRequest

  @redirect_uri "https://client.example.com/cb"
  @registered [@redirect_uri]

  # A syntactically valid S256 code_challenge: BASE64URL(SHA256(verifier)),
  # 43 chars, no padding (RFC 7636 §4.2). This is the RFC 7636 Appendix B
  # example challenge.
  @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  defp base_params(overrides \\ %{}) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => "client-123",
        "redirect_uri" => @redirect_uri,
        "scope" => "openid profile",
        "state" => "xyz",
        "nonce" => "n-0S6_WzA2Mj",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256"
      },
      overrides
    )
  end

  defp validate(params) do
    AuthorizationRequest.validate(params, registered_redirect_uris: @registered)
  end

  defp validate_require_nonce(params) do
    AuthorizationRequest.validate(params,
      registered_redirect_uris: @registered,
      require_nonce: true
    )
  end

  describe "validate/2 success" do
    test "accepts a valid OIDC authorization-code request" do
      assert {:ok, req} = validate(base_params())

      assert %AuthorizationRequest{
               response_type: "code",
               client_id: "client-123",
               redirect_uri: @redirect_uri,
               scope: ["openid", "profile"],
               openid?: true,
               state: "xyz",
               nonce: "n-0S6_WzA2Mj",
               code_challenge: @code_challenge,
               code_challenge_method: "S256",
               claims: %{}
             } = req
    end

    test "flags a plain OAuth (non-OIDC) request when the openid scope is absent" do
      assert {:ok, req} = validate(base_params(%{"scope" => "profile email"}))
      refute req.openid?
      assert req.scope == ["profile", "email"]
    end

    test "treats missing scope as empty and non-OIDC" do
      assert {:ok, req} = base_params() |> Map.delete("scope") |> validate()
      assert req.scope == []
      refute req.openid?
    end

    test "carries state and nonce through, nil when absent" do
      params = base_params() |> Map.drop(["state", "nonce"])
      assert {:ok, req} = validate(params)
      assert is_nil(req.state)
      assert is_nil(req.nonce)
    end

    test "parses optional prompt, max_age, and acr_values" do
      params =
        base_params(%{
          "prompt" => "login consent",
          "max_age" => "300",
          "acr_values" => "urn:mace:incommon:iap:silver phr"
        })

      assert {:ok, req} = validate(params)
      assert req.prompt == ["login", "consent"]
      assert req.max_age == 300
      assert req.acr_values == ["urn:mace:incommon:iap:silver", "phr"]
    end

    test "parses optional OIDC claims request object" do
      claims = %{
        "userinfo" => %{
          "name" => %{"essential" => true}
        }
      }

      assert {:ok, req} = validate(base_params(%{"claims" => JSON.encode!(claims)}))
      assert req.claims == claims
    end

    test "defaults optional params to empty / nil when absent" do
      assert {:ok, req} = validate(base_params())
      assert req.prompt == []
      assert req.acr_values == []
      assert is_nil(req.max_age)
      assert req.claims == %{}
    end
  end

  describe "validate/2 non-redirectable errors (OIDC Core §3.1.2.6)" do
    test "missing client_id does not redirect" do
      params = base_params() |> Map.delete("client_id")
      assert {:error, {:direct, :invalid_client_id}} = validate(params)
    end

    test "blank client_id does not redirect" do
      assert {:error, {:direct, :invalid_client_id}} = validate(base_params(%{"client_id" => ""}))
    end

    test "missing redirect_uri does not redirect" do
      params = base_params() |> Map.delete("redirect_uri")
      assert {:error, {:direct, :missing_redirect_uri}} = validate(params)
    end

    test "redirect_uri not in the registered set does not redirect" do
      params = base_params(%{"redirect_uri" => "https://attacker.example.com/cb"})
      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end

    test "redirect_uri must match exactly, not by prefix" do
      params = base_params(%{"redirect_uri" => @redirect_uri <> "/extra"})
      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end

    test "an empty registered set rejects every redirect_uri" do
      result = AuthorizationRequest.validate(base_params(), registered_redirect_uris: [])
      assert {:error, {:direct, :redirect_uri_not_registered}} = result
    end

    test "client_id and redirect_uri are checked before redirectable params" do
      # response_type is also bad, but the non-redirectable redirect_uri error
      # wins: an untrusted URI must never be redirected to (OIDC Core §3.1.2.6).
      params = base_params(%{"response_type" => "token", "redirect_uri" => "https://evil/cb"})
      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end
  end

  describe "validate/2 redirectable errors (RFC 6749 §4.1.2.1)" do
    test "missing response_type redirects with invalid_request" do
      params = base_params() |> Map.delete("response_type")
      assert {:error, {:redirect, err}} = validate(params)
      assert err.error == "invalid_request"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "unsupported response_type redirects with unsupported_response_type" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"response_type" => "token"}))
      assert err.error == "unsupported_response_type"
      assert err.redirect_uri == @redirect_uri
    end

    test "request_uri is explicitly rejected when unsupported" do
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"request_uri" => "https://rp.example/request.jwt"}))

      assert err.error == "request_uri_not_supported"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "request object is rejected when no trusted client keys are supplied" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"request" => "header.body.sig"}))

      assert err.error == "invalid_request_object"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "invalid request object with an untrusted redirect_uri does not redirect" do
      params =
        base_params(%{
          "request" => "header.body.sig",
          "redirect_uri" => "https://attacker.example/cb"
        })

      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end

    test "an out-of-ABNF scope token redirects with invalid_scope" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"scope" => "open\"id"}))
      assert err.error == "invalid_scope"
    end

    test "missing code_challenge redirects with invalid_request" do
      params = base_params() |> Map.delete("code_challenge")
      assert {:error, {:redirect, err}} = validate(params)
      assert err.error == "invalid_request"
      assert err.error_description =~ "code_challenge"
    end

    test "a syntactically invalid code_challenge redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"code_challenge" => "short"}))
      assert err.error == "invalid_request"
    end

    test "code_challenge_method=plain is rejected (RFC 7636 §4.4.1)" do
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"code_challenge_method" => "plain"}))

      assert err.error == "invalid_request"
      assert err.error_description =~ "plain"
    end

    test "missing code_challenge_method is rejected" do
      params = base_params() |> Map.delete("code_challenge_method")
      assert {:error, {:redirect, err}} = validate(params)
      assert err.error == "invalid_request"
      assert err.error_description =~ "S256"
    end

    test "an unknown code_challenge_method is rejected" do
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"code_challenge_method" => "S512"}))

      assert err.error == "invalid_request"
    end

    test "a non-integer max_age redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"max_age" => "soon"}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "max_age"
    end

    test "a negative max_age redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"max_age" => "-5"}))
      assert err.error == "invalid_request"
    end

    test "redirectable errors echo a nil state when state is absent" do
      params = base_params(%{"response_type" => "token"}) |> Map.delete("state")
      assert {:error, {:redirect, err}} = validate(params)
      assert is_nil(err.state)
    end

    test "an unknown prompt token redirects with invalid_request (OIDC Core §3.1.2.1)" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"prompt" => "login bogus"}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "prompt"
    end

    test "malformed claims redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"claims" => "{not json"}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "claims"
    end

    test "non-object claims redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"claims" => ~s(["name"])}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "claims"
    end
  end

  describe "validate/2 prompt parsing (OIDC Core §3.1.2.1)" do
    test "accepts each defined prompt value" do
      assert {:ok, req} = validate(base_params(%{"prompt" => "none"}))
      assert req.prompt == ["none"]

      assert {:ok, req} = validate(base_params(%{"prompt" => "login consent select_account"}))
      assert req.prompt == ["login", "consent", "select_account"]
    end

    test "absent prompt parses to an empty list" do
      params = base_params() |> Map.delete("prompt")
      assert {:ok, req} = validate(params)
      assert req.prompt == []
    end
  end

  describe "validate/2 require_nonce (OIDC Core §3.1.2.1)" do
    test "missing nonce with require_nonce: true redirects with invalid_request" do
      params = base_params() |> Map.delete("nonce")
      assert {:error, {:redirect, err}} = validate_require_nonce(params)
      assert err.error == "invalid_request"
      assert err.error_description =~ "nonce"
    end

    test "present nonce with require_nonce: true is ok" do
      assert {:ok, req} = validate_require_nonce(base_params(%{"nonce" => "n-0S6_WzA2Mj"}))
      assert req.nonce == "n-0S6_WzA2Mj"
    end

    test "nonce stays optional when require_nonce is off (default)" do
      params = base_params() |> Map.delete("nonce")
      assert {:ok, req} = validate(params)
      assert is_nil(req.nonce)
    end
  end
end
