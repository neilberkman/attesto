defmodule Attesto.PrincipalKindTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.PrincipalKind

  # `PrincipalKind.new/2`'s binary checks are a config-validation contract:
  # a host builds kinds from values that often come from external config
  # (a YAML/env/JSON file), so the constructor must reject a non-binary at
  # boot. These tests feed it exactly such a config-supplied value. The
  # value is passed at runtime (not as a static literal) on purpose: that
  # mirrors how the bad input actually arrives, and a static literal would
  # instead be caught by the Elixir 1.20 compile-time type checker - which
  # is correct, but is not the runtime contract these tests cover.
  # `Process.get/2` with an unset key returns its default and gives the
  # value a runtime (non-static) provenance.
  defp from_config(value), do: Process.get(:__attesto_test_unset__, value)

  describe "new/3 success" do
    test "builds a kind with no required claims" do
      kind = PrincipalKind.new("client", "oc_")

      assert %PrincipalKind{
               claim_value: "client",
               sub_prefix: "oc_",
               required_claims: []
             } = kind
    end

    test "builds a kind with required claims preserving order and shapes" do
      kind =
        PrincipalKind.new("user", "usr_",
          required_claims: [
            {"act", :non_empty_string},
            {"sid", :non_empty_string},
            {"token_version", :non_neg_integer}
          ]
        )

      assert kind.required_claims == [
               {"act", :non_empty_string},
               {"sid", :non_empty_string},
               {"token_version", :non_neg_integer}
             ]
    end

    test "accepts the :string shape" do
      kind = PrincipalKind.new("device", "dev_", required_claims: [{"label", :string}])
      assert kind.required_claims == [{"label", :string}]
    end
  end

  describe "new/3 validation" do
    test "raises on empty claim_value" do
      assert_raise ArgumentError, fn -> PrincipalKind.new("", "oc_") end
    end

    test "raises on non-binary claim_value" do
      # A non-binary claim_value (atom) arriving from host config.
      assert_raise ArgumentError, fn -> PrincipalKind.new(from_config(:client), "oc_") end
    end

    test "raises on empty sub_prefix" do
      assert_raise ArgumentError, fn -> PrincipalKind.new("client", "") end
    end

    test "raises on non-binary sub_prefix" do
      # A nil sub_prefix arriving from host config (a missing key).
      assert_raise ArgumentError, fn -> PrincipalKind.new("client", from_config(nil)) end
    end

    test "raises on an unknown required-claim shape" do
      assert_raise ArgumentError, fn ->
        PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :uuid}])
      end
    end

    test "raises when a required-claim entry has a non-binary name" do
      assert_raise ArgumentError, fn ->
        PrincipalKind.new("client", "oc_", required_claims: [{:client_id, :non_empty_string}])
      end
    end

    test "raises when a required-claim entry is not a {name, shape} tuple" do
      assert_raise ArgumentError, fn ->
        PrincipalKind.new("client", "oc_", required_claims: ["client_id"])
      end
    end

    test "raises when required_claims is not a list" do
      assert_raise ArgumentError, fn ->
        PrincipalKind.new("client", "oc_", required_claims: %{"client_id" => :non_empty_string})
      end
    end
  end

  describe "check_required/2" do
    test "returns :ok when there are no required claims, regardless of the map" do
      kind = PrincipalKind.new("client", "oc_")
      assert PrincipalKind.check_required(kind, %{}) == :ok
      assert PrincipalKind.check_required(kind, %{"anything" => "here"}) == :ok
    end

    test "returns :ok when every required claim is present with the right shape" do
      kind =
        PrincipalKind.new("user", "usr_",
          required_claims: [
            {"act", :non_empty_string},
            {"sid", :non_empty_string},
            {"token_version", :non_neg_integer}
          ]
        )

      claims = %{"act" => "acc_1", "sid" => "sess_1", "token_version" => 0}
      assert PrincipalKind.check_required(kind, claims) == :ok
    end

    test "returns {:error, {name, :missing}} for an absent claim" do
      kind = PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
      assert PrincipalKind.check_required(kind, %{}) == {:error, {"client_id", :missing}}
    end

    test "reports the first violation in declaration order" do
      kind =
        PrincipalKind.new("user", "usr_",
          required_claims: [
            {"act", :non_empty_string},
            {"sid", :non_empty_string}
          ]
        )

      # Both missing; "act" comes first.
      assert PrincipalKind.check_required(kind, %{}) == {:error, {"act", :missing}}
    end

    test ":non_empty_string rejects an empty string as :wrong_shape" do
      kind = PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])

      assert PrincipalKind.check_required(kind, %{"client_id" => ""}) ==
               {:error, {"client_id", :wrong_shape}}
    end

    test ":non_empty_string rejects a non-binary value as :wrong_shape" do
      kind = PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])

      assert PrincipalKind.check_required(kind, %{"client_id" => 123}) ==
               {:error, {"client_id", :wrong_shape}}
    end

    test ":non_neg_integer rejects a negative integer as :wrong_shape" do
      kind = PrincipalKind.new("user", "usr_", required_claims: [{"token_version", :non_neg_integer}])

      assert PrincipalKind.check_required(kind, %{"token_version" => -1}) ==
               {:error, {"token_version", :wrong_shape}}
    end

    test ":non_neg_integer rejects a non-integer as :wrong_shape" do
      kind = PrincipalKind.new("user", "usr_", required_claims: [{"token_version", :non_neg_integer}])

      assert PrincipalKind.check_required(kind, %{"token_version" => "3"}) ==
               {:error, {"token_version", :wrong_shape}}
    end

    test ":non_neg_integer accepts zero" do
      kind = PrincipalKind.new("user", "usr_", required_claims: [{"token_version", :non_neg_integer}])
      assert PrincipalKind.check_required(kind, %{"token_version" => 0}) == :ok
    end

    test ":string accepts the empty string" do
      kind = PrincipalKind.new("device", "dev_", required_claims: [{"label", :string}])
      assert PrincipalKind.check_required(kind, %{"label" => ""}) == :ok
    end

    test ":string rejects a non-binary value as :wrong_shape" do
      kind = PrincipalKind.new("device", "dev_", required_claims: [{"label", :string}])

      assert PrincipalKind.check_required(kind, %{"label" => 1}) ==
               {:error, {"label", :wrong_shape}}
    end
  end
end
