defmodule Attesto.CodeStoreContract do
  @moduledoc false
  # Reusable conformance suite for any `Attesto.CodeStore` implementation.
  #
  # `use` this module from a test case to inject the shared security
  # contract for code stores. The same tests run against any store, so the
  # ETS reference today and a SQL store tomorrow are held to the identical
  # single-use / atomic-take guarantees that authorization-code redemption
  # safety rests on.
  #
  # ## Options
  #
  #   * `:store` (required) - the module implementing `Attesto.CodeStore`.
  #   * `:start` (optional) - a 0-arity fun that starts the store and
  #     returns its pid (or `{:ok, pid}`). When omitted, the suite calls
  #     `start_supervised!(store)`.
  #
  # The store under test is typically a named singleton GenServer, so the
  # host case MUST be `use ExUnit.Case, async: false`.
  #
  #     defmodule MyStoreContractTest do
  #       use ExUnit.Case, async: false
  #       use Attesto.CodeStoreContract, store: My.CodeStore
  #     end

  defmacro __using__(opts) do
    store = Keyword.fetch!(opts, :store)
    start = Keyword.get(opts, :start)

    start_call =
      if start,
        do: quote(do: unquote(start).()),
        else: quote(do: start_supervised!(unquote(store)))

    quote do
      @contract_store unquote(store)

      setup do
        unquote(start_call)
        :ok
      end

      # A plain map matching the documented `Attesto.CodeStore.record`
      # shape. `expires_at` defaults far in the future so the record is
      # present and unexpired unless a test overrides it.
      defp contract_code_record(overrides \\ %{}) do
        suffix = 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

        %{
          code_hash: "code_hash_" <> suffix,
          data: %{
            client_id: "oc_example",
            redirect_uri: "https://app.example.com/callback",
            scope: "things.read",
            sub: "usr_example"
          },
          expires_at: System.system_time(:second) + 600
        }
        |> Map.merge(overrides)
      end

      test "put then take returns the stored record" do
        record = contract_code_record()

        assert :ok = @contract_store.put(record)
        assert {:ok, taken} = @contract_store.take(record.code_hash)
        assert taken == record
      end

      test "take is single use: the second take of the same code is :error" do
        record = contract_code_record()
        :ok = @contract_store.put(record)

        assert {:ok, ^record} = @contract_store.take(record.code_hash)
        assert :error = @contract_store.take(record.code_hash)
      end

      test "take of an absent code is :error" do
        assert :error = @contract_store.take("code_hash_never_stored")
      end

      test "an expired-but-present record is still returned by take (store does not gate expiry)" do
        # The store hands back the row; expiry is re-checked by the caller
        # (`Attesto.AuthorizationCode`) after take, never by the store.
        expired = contract_code_record(%{expires_at: System.system_time(:second) - 600})
        :ok = @contract_store.put(expired)

        assert {:ok, ^expired} = @contract_store.take(expired.code_hash)
      end
    end
  end
end
