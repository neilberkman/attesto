defmodule Attesto.IntrospectionTest do
  @moduledoc false
  # Factory.config installs key material into the application env.
  use ExUnit.Case, async: false

  alias Attesto.Introspection
  alias Attesto.Secret
  alias Attesto.Test.Factory
  alias Attesto.Token

  setup do
    {:ok, config: Factory.config(Factory.rsa_pem())}
  end

  defp client_principal(overrides \\ %{}) do
    Map.merge(
      %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
      overrides
    )
  end

  describe "introspect/3 - access tokens" do
    test "an active access token is described with the RFC 7662 members", %{config: config} do
      now = 1_700_000_000

      {:ok, %{access_token: jwt}} =
        Token.mint(config, client_principal(%{scopes: ["documents.read", "positions.read"]}), now: now)

      response = Introspection.introspect(config, jwt, now: now)

      assert response["active"] == true
      assert response["scope"] == "documents.read positions.read"
      assert response["sub"] == "oc_abc123"
      assert response["client_id"] == "oc_abc123"
      assert response["iss"] == config.issuer
      assert response["aud"] == config.audience
      assert is_integer(response["exp"])
      assert is_integer(response["iat"])
      assert is_binary(response["jti"])
      assert response["token_type"] == "Bearer"
    end

    test "an expired access token is inactive (no existence oracle)", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      # Introspect well after expiry.
      assert Introspection.introspect(config, jwt, now: now + 100_000) == %{"active" => false}
    end

    test "a garbage or forged token is inactive", %{config: config} do
      assert Introspection.introspect(config, "not-a-jwt", now: 1_700_000_000) == %{"active" => false}
      assert Introspection.introspect(config, "a.b.c", now: 1_700_000_000) == %{"active" => false}
    end

    test "a sender-constrained token is active and echoes cnf with token_type DPoP", %{config: config} do
      now = 1_700_000_000
      jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

      {:ok, %{access_token: jwt}} =
        Token.mint(config, client_principal(), now: now, dpop_jkt: jkt)

      # No proof key is presented at introspection - activeness must not depend
      # on the confirmation binding.
      response = Introspection.introspect(config, jwt, now: now)

      assert response["active"] == true
      assert response["token_type"] == "DPoP"
      assert response["cnf"] == %{"jkt" => jkt}
    end
  end

  describe "introspect/3 - refresh tokens" do
    defmodule StubRefreshStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def get(hash) do
        case :persistent_term.get({__MODULE__, hash}, :error) do
          :error -> :error
          entry -> {:ok, entry}
        end
      end

      @impl true
      def insert(_entry), do: :ok
      @impl true
      def consume(_hash, _opts), do: :error
      @impl true
      def remember_successor(_hash, _data, _opts), do: :ok
      @impl true
      def revoke_family(_family_id), do: :ok

      def put(token, entry), do: :persistent_term.put({__MODULE__, Secret.hash(token)}, entry)
    end

    test "a stored, unexpired refresh token is active (minimal members)", %{config: config} do
      now = 1_700_000_000
      StubRefreshStore.put("refresh-xyz", %{family_id: "fam-1", expires_at: now + 1000, data: %{}})

      response =
        Introspection.introspect(config, "refresh-xyz",
          now: now,
          refresh_store: StubRefreshStore,
          token_type_hint: "refresh_token"
        )

      assert response == %{"active" => true, "exp" => now + 1000}
    end

    test "an unknown refresh token is inactive", %{config: config} do
      assert Introspection.introspect(config, "nope",
               now: 1_700_000_000,
               refresh_store: StubRefreshStore
             ) == %{"active" => false}
    end
  end
end
