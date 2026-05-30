defmodule Attesto.AuthorizationCode.GrantTest do
  @moduledoc false
  # Pure unit tests for Grant.from_data/1, the projection redeem/4 returns.
  # No store, no clock: async: true.
  use ExUnit.Case, async: true

  alias Attesto.AuthorizationCode.Grant

  @client_id "oc_app"
  @redirect_uri "https://app.example.com/cb"
  @subject "usr_42"

  defp data(overrides \\ %{}) do
    Map.merge(
      %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        subject: @subject,
        scope: ["documents.read"],
        dpop_jkt: nil,
        claims: %{}
      },
      overrides
    )
  end

  describe "from_data/1" do
    test "projects the stored grant context onto the struct" do
      jkt = "dpopkeythumbprintvalue000000000000000000000"
      claims = %{"tenant" => "acme"}

      grant = Grant.from_data(data(%{dpop_jkt: jkt, claims: claims}))

      assert %Grant{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               subject: @subject,
               scope: ["documents.read"],
               dpop_jkt: ^jkt,
               claims: ^claims
             } = grant
    end

    test "defaults scope to [] when absent" do
      stored = data() |> Map.delete(:scope)
      assert %Grant{scope: []} = Grant.from_data(stored)
    end

    test "defaults claims to %{} when absent" do
      stored = data() |> Map.delete(:claims)
      assert %Grant{claims: %{}} = Grant.from_data(stored)
    end

    test "defaults dpop_jkt to nil when absent" do
      stored = data() |> Map.delete(:dpop_jkt)
      assert %Grant{dpop_jkt: nil} = Grant.from_data(stored)
    end

    test "preserves an explicit empty scope list" do
      assert %Grant{scope: []} = Grant.from_data(data(%{scope: []}))
    end
  end

  describe "struct enforcement" do
    test "requires client_id, redirect_uri, and subject" do
      assert_raise ArgumentError, fn ->
        struct!(Grant, redirect_uri: @redirect_uri, subject: @subject)
      end
    end
  end
end
