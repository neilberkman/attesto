defmodule Attesto.ConcurrencyNonceTest do
  @moduledoc false
  # Contention floods for `Attesto.DPoP.NonceStore.ETS`, in the spirit of
  # `Attesto.ConcurrencySwarmTest`: where `dpop_nonce_test.exs` proves the
  # single-threaded contract (issue mints, valid?/validate report liveness),
  # these prove the SAME invariants survive a swarm of concurrent issuers and
  # readers. The store is a `:set` ETS table with read/write concurrency, so
  # under load the things that must hold are:
  #
  #   1. Concurrent `issue/1` mints DISTINCT nonces. The single-threaded test
  #      only checks two sequential issues differ (dpop_nonce_test.exs line
  #      206-208). Each nonce is 128 bits from `:crypto.strong_rand_bytes/1`
  #      and the table is keyed on the nonce, so even if two racers somehow
  #      collided the second `:ets.insert` would clobber the first row and the
  #      store would silently hold fewer rows than nonces handed out. A swarm
  #      catches both: collisions in the returned set AND lost rows.
  #
  #   2. Concurrent `valid?/1` reads of a live nonce all see true. A reader
  #      racing other readers (or sweeps) must never get a false negative on a
  #      nonce that is genuinely live, or a real client would be told to retry
  #      with a fresh nonce for no reason.
  #
  #   3. issue + immediate valid?/validate churn: a freshly issued nonce is
  #      visible to a concurrent reader the instant `issue/1` returns. ETS
  #      insert is atomic and synchronous, so there is no window where the
  #      caller holds a nonce the table has not yet committed; a flood of
  #      "issue then read it back" tasks must show zero misses.
  #
  # `NonceStore.ETS` is a named singleton (its table is a `:named_table`
  # owned by the GenServer), so it is `start_supervised!`-ed once per test and
  # this module runs `async: false`.
  use ExUnit.Case, async: false

  alias Attesto.DPoP.NonceStore.ETS, as: NonceStore

  @swarm 30
  @await_ms 5_000

  setup do
    start_supervised!(NonceStore)
    :ok
  end

  defp swarm(fun) do
    1..@swarm
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(@await_ms)
  end

  describe "issue swarm: concurrent minting collides on nothing" do
    test "every parallel issue/1 returns a distinct nonce" do
      nonces = swarm(fn -> NonceStore.issue(300) end)

      assert length(nonces) == @swarm

      # Every racer got a well-formed nonce: a 22-char unpadded base64url
      # string, exactly as the single-threaded test asserts for one nonce.
      assert Enum.all?(nonces, fn n ->
               is_binary(n) and String.length(n) == 22 and n =~ ~r/\A[A-Za-z0-9_-]+\z/
             end),
             "every issued nonce must be a 22-char base64url string; got #{inspect(nonces)}"

      # No two racers minted the same nonce. 128 bits of randomness makes a
      # collision astronomically unlikely; what this really guards is that the
      # store does not, say, derive the nonce from a shared mutable counter.
      assert nonces |> Enum.uniq() |> length() == @swarm,
             "concurrent issue/1 must mint distinct nonces; got a collision in #{inspect(nonces)}"

      # And the store actually holds a live row for every nonce it handed out:
      # if two racers had collided on a key the second insert would have
      # clobbered the first row, leaving a nonce in `nonces` that reads as
      # unknown. valid?/1 over the whole set proves no row was lost.
      assert Enum.all?(nonces, &NonceStore.valid?/1),
             "every concurrently issued nonce must be live in the store afterwards"
    end
  end

  describe "valid? swarm: concurrent reads of one live nonce never false-negative" do
    test "every parallel valid?/1 of an issued nonce returns true" do
      nonce = NonceStore.issue(300)

      results = swarm(fn -> NonceStore.valid?(nonce) end)

      assert length(results) == @swarm

      # A live nonce read under read-contention is always true: no reader may
      # be told a genuinely-live nonce is stale.
      assert Enum.all?(results, &(&1 == true)),
             "concurrent reads of a live nonce must all be true; got #{inspect(results)}"
    end

    test "every parallel validate/1 of an issued nonce returns :ok" do
      nonce = NonceStore.issue(300)

      results = swarm(fn -> NonceStore.validate(nonce) end)

      assert length(results) == @swarm

      # The :nonce_check-shaped surface holds the same invariant: a live nonce
      # is :ok for every concurrent caller, never a spurious :use_dpop_nonce.
      assert Enum.all?(results, &(&1 == :ok)),
             "concurrent validate/1 of a live nonce must all be :ok; got #{inspect(results)}"
    end
  end

  describe "issue + valid? churn: a just-issued nonce is immediately visible" do
    test "each task that issues then reads its own nonce back sees it live" do
      # Each racer mints its own nonce and reads it straight back. Because
      # `:ets.insert` is atomic and synchronous, the row is committed before
      # `issue/1` returns, so the immediate `valid?/1` must always be true even
      # while @swarm-1 other tasks are inserting and reading concurrently.
      results =
        swarm(fn ->
          nonce = NonceStore.issue(300)
          {nonce, NonceStore.valid?(nonce)}
        end)

      assert length(results) == @swarm

      assert Enum.all?(results, fn {_nonce, live?} -> live? == true end),
             "a nonce must be live the instant issue/1 returns; got #{inspect(results)}"

      # The churn also produced @swarm distinct nonces (no insert clobbered a
      # peer's row mid-flight): the set of issued nonces is collision-free.
      nonces = Enum.map(results, fn {nonce, _} -> nonce end)

      assert nonces |> Enum.uniq() |> length() == @swarm,
             "issue/valid? churn must still mint distinct nonces; got #{inspect(nonces)}"
    end

    test "a reader swarm racing one issuer sees the nonce live once issued" do
      # One nonce, then @swarm validators read it concurrently. This is the
      # mixed read path: validate/1 of a committed nonce never races into a
      # false negative regardless of how many readers hit the table at once.
      nonce = NonceStore.issue(300)

      results =
        swarm(fn ->
          # Read it a handful of times in each task to widen the contention
          # window; every read of this committed nonce must be :ok.
          Enum.map(1..5, fn _ -> NonceStore.validate(nonce) end)
        end)

      assert length(results) == @swarm

      assert Enum.all?(results, fn reads -> Enum.all?(reads, &(&1 == :ok)) end),
             "repeated concurrent reads of a live nonce must all be :ok; got #{inspect(results)}"
    end
  end
end
