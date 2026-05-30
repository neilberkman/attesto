defmodule Attesto.RefreshStoreContract do
  @moduledoc false
  # Reusable conformance suite for any `Attesto.RefreshStore` implementation.
  #
  # `use` this module from a test case to inject the shared security
  # contract for refresh-token stores. The same tests run against any
  # store, so the ETS reference today and a SQL store tomorrow are held to
  # the identical atomic-consume and family-revocation guarantees that
  # refresh-token reuse detection rests on.
  #
  # ## Options
  #
  #   * `:store` (required) - the module implementing `Attesto.RefreshStore`.
  #   * `:start` (optional) - a 0-arity fun that starts the store and
  #     returns its pid (or `{:ok, pid}`). When omitted, the suite calls
  #     `start_supervised!(store)`.
  #
  # The store under test is typically a named singleton GenServer, so the
  # host case MUST be `use ExUnit.Case, async: false`.
  #
  #     defmodule MyStoreContractTest do
  #       use ExUnit.Case, async: false
  #       use Attesto.RefreshStoreContract, store: My.RefreshStore
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

      # A plain map matching the documented `Attesto.RefreshStore.record`
      # shape. Fresh, unconsumed, unexpired unless a test overrides it.
      defp contract_refresh_record(overrides \\ %{}) do
        token_suffix = 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
        family_suffix = 8 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

        %{
          token_hash: "token_hash_" <> token_suffix,
          family_id: "fam_" <> family_suffix,
          generation: 0,
          data: %{
            sub: "usr_example",
            scope: "things.read",
            client_id: "oc_example"
          },
          expires_at: System.system_time(:second) + 3600,
          consumed: false
        }
        |> Map.merge(overrides)
      end

      test "insert then get returns the record, still unconsumed" do
        record = contract_refresh_record()

        assert :ok = @contract_store.insert(record)
        assert {:ok, got} = @contract_store.get(record.token_hash)
        assert got == record
        assert got.consumed == false
      end

      test "consume of an unconsumed token returns {:ok, record} and marks it consumed" do
        record = contract_refresh_record()
        :ok = @contract_store.insert(record)

        assert {:ok, ^record} = @contract_store.consume(record.token_hash)

        # The mark stuck: a subsequent non-consuming read sees it consumed.
        assert {:ok, after_consume} = @contract_store.get(record.token_hash)
        assert after_consume.consumed == true
      end

      test "a second consume of the same token returns {:reuse, record}" do
        record = contract_refresh_record()
        :ok = @contract_store.insert(record)

        assert {:ok, _} = @contract_store.consume(record.token_hash)
        assert {:reuse, reused} = @contract_store.consume(record.token_hash)
        assert reused.token_hash == record.token_hash
        assert reused.family_id == record.family_id
      end

      test "consume of an absent token is :error" do
        assert :error = @contract_store.consume("token_hash_never_stored")
      end

      test "get is non-consuming: get after get leaves the token unconsumed" do
        record = contract_refresh_record()
        :ok = @contract_store.insert(record)

        assert {:ok, first} = @contract_store.get(record.token_hash)
        assert first.consumed == false
        assert {:ok, second} = @contract_store.get(record.token_hash)
        assert second.consumed == false

        # And consume still succeeds, proving the gets never claimed it.
        assert {:ok, _} = @contract_store.consume(record.token_hash)
      end

      test "revoke_family removes exactly the matching family" do
        target_family = "fam_target"
        keep_family = "fam_keep"

        target_a = contract_refresh_record(%{family_id: target_family})
        target_b = contract_refresh_record(%{family_id: target_family, generation: 1})
        keep_a = contract_refresh_record(%{family_id: keep_family})
        keep_b = contract_refresh_record(%{family_id: keep_family, generation: 1})

        for record <- [target_a, target_b, keep_a, keep_b] do
          :ok = @contract_store.insert(record)
        end

        assert :ok = @contract_store.revoke_family(target_family)

        # The target family is gone from both read paths.
        assert :error = @contract_store.get(target_a.token_hash)
        assert :error = @contract_store.get(target_b.token_hash)
        assert :error = @contract_store.consume(target_a.token_hash)
        assert :error = @contract_store.consume(target_b.token_hash)

        # The other family is untouched and still consumable.
        assert {:ok, _} = @contract_store.get(keep_a.token_hash)
        assert {:ok, _} = @contract_store.get(keep_b.token_hash)
        assert {:ok, _} = @contract_store.consume(keep_a.token_hash)
      end

      test "revoke_family is idempotent: revoking twice is fine" do
        record = contract_refresh_record(%{family_id: "fam_idem"})
        :ok = @contract_store.insert(record)

        assert :ok = @contract_store.revoke_family("fam_idem")
        assert :ok = @contract_store.revoke_family("fam_idem")
        # Revoking a family that was never present is also a no-op success.
        assert :ok = @contract_store.revoke_family("fam_never_existed")

        assert :error = @contract_store.get(record.token_hash)
      end

      test "revocation is sticky: a later insert into a revoked family is refused" do
        # The concurrency guarantee reuse detection depends on: once a
        # family is revoked, a successor that arrives afterwards (e.g. a
        # rotation that won its claim but inserts after the revoke) MUST be
        # rejected, not stored, so the family cannot fork back to life.
        assert :ok = @contract_store.revoke_family("fam_sticky")

        late = contract_refresh_record(%{family_id: "fam_sticky"})
        assert {:error, :family_revoked} = @contract_store.insert(late)
        assert :error = @contract_store.get(late.token_hash)
      end
    end
  end
end
