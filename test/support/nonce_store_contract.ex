defmodule Attesto.NonceStoreContract do
  @moduledoc false
  # Reusable conformance suite for any `Attesto.DPoP.NonceStore` implementation.
  #
  # `use` this module from a test case to inject the shared contract for
  # server-issued DPoP nonce stores (RFC 9449 §8). The same tests run against
  # any store, so the bundled single-node ETS reference today and a shared
  # multi-node store tomorrow are held to the identical issue/valid?
  # guarantees that DPoP nonce challenges rest on: every issued nonce is
  # distinct, an issued nonce reads live until its ttl elapses and dead
  # after, and a non-binary nonce is never live.
  #
  # The contract exercises only the two behaviour callbacks an implementation
  # MUST provide: `issue/1` and `valid?/1`. Implementation extras such as the
  # ETS store's `validate/1` (`:nonce_check` shape) and `reset/0` are covered
  # by that store's own `dpop_nonce_test.exs`, not here.
  #
  # ## Options
  #
  #   * `:store` (required) - the module implementing `Attesto.DPoP.NonceStore`.
  #   * `:start` (optional) - a 0-arity fun that starts the store and
  #     returns its pid (or `{:ok, pid}`). When omitted, the suite calls
  #     `start_supervised!(store)`.
  #
  # The store under test is typically a named singleton GenServer, so the
  # host case MUST be `use ExUnit.Case, async: false`.
  #
  #     defmodule MyNonceStoreContractTest do
  #       use ExUnit.Case, async: false
  #       use Attesto.NonceStoreContract, store: My.NonceStore
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

      # A ttl (in whole seconds) that keeps an issued nonce comfortably live
      # for the duration of a single test, so liveness assertions never race
      # the store's own clock.
      defp contract_live_ttl, do: 600

      # ---------------------------------------------------------------
      # issue/1 and valid?/1, the live path
      # ---------------------------------------------------------------

      test "issue/1 returns a binary nonce that valid?/1 reports live" do
        nonce = @contract_store.issue(contract_live_ttl())

        assert is_binary(nonce)
        assert @contract_store.valid?(nonce)
      end

      test "valid?/1 is false for a nonce this store never issued" do
        # The store must not vouch for an opaque string it did not mint.
        refute @contract_store.valid?("never-issued-by-this-store")
      end

      test "issue is lock-free yet every issued nonce is distinct" do
        # Nonce minting takes no lock, so the only thing standing between two
        # issues and a collision is the randomness of the nonce itself. Mint a
        # batch and assert there are no duplicates: a repeat would let a client
        # replay one node's challenge answer against another issuance.
        nonces = for _ <- 1..1_000, do: @contract_store.issue(contract_live_ttl())

        assert length(Enum.uniq(nonces)) == length(nonces)
      end

      test "every distinct issued nonce is independently live" do
        # Distinctness must not come at the cost of liveness: each minted
        # nonce, not merely the last one, validates.
        nonces = for _ <- 1..50, do: @contract_store.issue(contract_live_ttl())

        for nonce <- nonces do
          assert @contract_store.valid?(nonce)
        end
      end

      # ---------------------------------------------------------------
      # concurrency: parallel issue/valid? stays consistent
      # ---------------------------------------------------------------

      test "concurrent issuers get distinct nonces, each of which validates" do
        # Many tasks mint at once against the lock-free path. Collisions or a
        # lost write would surface here as a duplicate nonce or a freshly
        # minted nonce that does not read live.
        nonces =
          1..200
          |> Task.async_stream(
            fn _ -> @contract_store.issue(contract_live_ttl()) end,
            max_concurrency: 50,
            ordered: false
          )
          |> Enum.map(fn {:ok, nonce} -> nonce end)

        assert length(Enum.uniq(nonces)) == length(nonces)

        for nonce <- nonces do
          assert @contract_store.valid?(nonce)
        end
      end

      # ---------------------------------------------------------------
      # ttl boundary: live just before expiry, dead at/after expiry
      # ---------------------------------------------------------------

      test "valid?/1 is true for a nonce issued with a generous ttl (just before expiry)" do
        # A nonce minted with a long ttl reads live throughout the test: the
        # "just before expiry" side of the boundary.
        nonce = @contract_store.issue(contract_live_ttl())

        assert @contract_store.valid?(nonce)
      end

      test "valid?/1 is false once a short-ttl nonce's lifetime has elapsed (at/after expiry)" do
        # The "at/after expiry" side of the boundary. We mint with a 1-second
        # ttl, then spin (no Process.sleep) until whole-second system time --
        # the clock the ETS store stamps and compares against -- has advanced
        # strictly past the issuance second, so the nonce's expiry stamp is in
        # the past and `valid?` must read false.
        nonce = @contract_store.issue(1)
        issued_at = System.system_time(:second)
        contract_wait_until_clock_passes(issued_at + 1)

        refute @contract_store.valid?(nonce)
      end

      # ---------------------------------------------------------------
      # non-binary / nil nonces are never live
      # ---------------------------------------------------------------

      test "valid?/1 is false for nil and other non-binary nonces" do
        # `valid?` accepts only a binary; everything else -- including the nil
        # a proof with no `nonce` claim presents -- is not a live nonce.
        refute @contract_store.valid?(nil)
        refute @contract_store.valid?(:not_a_nonce)
        refute @contract_store.valid?(12_345)
        refute @contract_store.valid?(~c"charlist-not-binary")
        refute @contract_store.valid?(%{nonce: "wrapped"})
      end

      # Spin until whole-second system time (the clock the store stamps and
      # compares against) has advanced strictly past `target`, so an expiry
      # stamp at or before `target` is strictly in the past.
      defp contract_wait_until_clock_passes(target) do
        if System.system_time(:second) > target do
          :ok
        else
          contract_wait_until_clock_passes(target)
        end
      end
    end
  end
end
