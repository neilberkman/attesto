defmodule Attesto.MetadataHardeningTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Config
  alias Attesto.Discovery
  alias Attesto.Keystore.Static
  alias Attesto.PrincipalKind

  defp config(overrides) do
    [
      issuer: "https://auth.example.com/",
      audience: "https://api.example.com/",
      keystore: Static,
      principal_kinds: [PrincipalKind.new("client", "oc_")]
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  describe "RFC 8414 §2 issuer URL shape (Config.new)" do
    test "an https issuer with a host and no query/fragment is accepted" do
      assert %Config{} = config(issuer: "https://auth.example.com/")
      assert %Config{} = config(issuer: "https://auth.example.com/tenant/1")
    end

    test "a non-https issuer is rejected" do
      assert_raise ArgumentError, ~r/https URL/, fn -> config(issuer: "http://auth.example.com/") end
    end

    test "an issuer without a host is rejected" do
      assert_raise ArgumentError, ~r/must include a host/, fn -> config(issuer: "https:///x") end
    end

    test "an issuer carrying a query is rejected" do
      assert_raise ArgumentError, ~r/query/, fn -> config(issuer: "https://auth.example.com/?a=1") end
    end

    test "an issuer carrying a fragment is rejected" do
      assert_raise ArgumentError, ~r/fragment/, fn -> config(issuer: "https://auth.example.com/#x") end
    end
  end

  describe "RFC 8705 / PAR metadata pass-through (Discovery.metadata)" do
    test "tls_client_certificate_bound_access_tokens is advertised when supplied" do
      meta = Discovery.metadata(config([]), tls_client_certificate_bound_access_tokens: true)
      assert meta["tls_client_certificate_bound_access_tokens"] == true
    end

    test "mtls_endpoint_aliases is passed through" do
      aliases = %{"token_endpoint" => "https://mtls.auth.example.com/oauth/token"}
      meta = Discovery.metadata(config([]), mtls_endpoint_aliases: aliases)
      assert meta["mtls_endpoint_aliases"] == aliases
    end

    test "revocation and PAR endpoint fields pass through" do
      meta =
        Discovery.metadata(config([]),
          revocation_endpoint: "https://auth.example.com/revoke",
          pushed_authorization_request_endpoint: "https://auth.example.com/par",
          require_pushed_authorization_requests: true
        )

      assert meta["revocation_endpoint"] == "https://auth.example.com/revoke"
      assert meta["pushed_authorization_request_endpoint"] == "https://auth.example.com/par"
      assert meta["require_pushed_authorization_requests"] == true
    end

    test "unsupplied extension fields are absent" do
      meta = Discovery.metadata(config([]))
      refute Map.has_key?(meta, "tls_client_certificate_bound_access_tokens")
      refute Map.has_key?(meta, "mtls_endpoint_aliases")
    end
  end
end
