defmodule Attesto.ConcurrencySwarmTest do
  @moduledoc false
  # Contention floods that extend the two-way race tests in
  # `Attesto.GrantsConcurrencyTest` from a pair of racers to a swarm of N.
  # Where the two-way tests prove the atomic primitive admits at most one
  # winner, these prove the SAME invariants hold under heavy contention and
  # that the conservative responses (family revocation, replay rejection)
  # are idempotent: no second successor is ever minted, no two distinct
  # proofs both win the replay CAS.
  #
  # Named-singleton stores (RefreshStore.ETS, DPoP.ReplayCache) plus the
  # DPoP factory's reliance on shared crypto material => async: false.
  use ExUnit.Case, async: false

  alias Attesto.DPoP
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Test.Factory

  @swarm 30
  @await_ms 5_000

  setup do
    start_supervised!(RefreshStore.ETS)
    start_supervised!(DPoP.ReplayCache)
    :ok
  end

  defp swarm(fun) do
    1..@swarm
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(@await_ms)
  end

  describe "reuse swarm: flooded rotation of an already-consumed token" do
    test "every parallel rotation of the consumed original is :reuse_detected and revocation is idempotent" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", scope: ["documents.read"]})

      # Rotate once: t0 is now consumed, and a live successor (t1) exists.
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0)
      assert is_binary(t1)
      refute t1 == t0

      # Fire a flood of rotations of the ALREADY-CONSUMED original. Each one
      # is a replay of a rotated token: the attack signal. The first racer
      # reads consumed=true and revokes the whole family, which (in the ETS
      # store) match-deletes the original's row too; racers that read after
      # the delete see an unknown token and report :invalid_grant. So every
      # result is one of {:reuse_detected, :invalid_grant}, and crucially
      # NONE is {:ok}: no replay of a consumed token ever mints a successor.
      # The repeated revoke_family/1 calls must be idempotent (no crash, the
      # family simply stays revoked), and at least one racer must have seen
      # the reuse signal directly.
      results = swarm(fn -> RefreshToken.rotate(RefreshStore.ETS, t0) end)

      assert length(results) == @swarm

      assert Enum.all?(results, fn r ->
               r == {:error, :reuse_detected} or r == {:error, :invalid_grant}
             end),
             "replaying a consumed token must never mint a successor; got #{inspect(results)}"

      assert Enum.any?(results, &(&1 == {:error, :reuse_detected})),
             "at least one racer must observe the reuse signal directly"

      refute Enum.any?(results, &match?({:ok, _}, &1)),
             "no replay of a consumed token may mint a successor"

      # The family is revoked. revoke_family/1 in the ETS store match-deletes
      # every row for the family_id, so the live successor t1 is gone too:
      # rotating it now is an unknown-token :invalid_grant. Either way the
      # successor no longer rotates - no live token survives the revocation.
      refute match?({:ok, _}, RefreshToken.rotate(RefreshStore.ETS, t1)),
             "the live successor must not rotate once the family is revoked"

      # And the consumed original still cannot be turned into a successor:
      # the family stays revoked under repeated pressure.
      assert RefreshToken.rotate(RefreshStore.ETS, t0) in [
               {:error, :reuse_detected},
               {:error, :invalid_grant}
             ]

      # No second successor was ever minted: the only tokens that ever
      # existed in this family are t0 (consumed/revoked) and t1 (revoked).
      # Confirm the family carries no rotatable token at all.
      assert RefreshStore.ETS.get(Attesto.Secret.hash(t1)) == :error,
             "successor row must have been revoked, leaving the family forkless"
    end
  end

  describe "claim swarm: flooded rotation of one live token" do
    test "at most one rotation claims the live token; the family ends revoked and forkless" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_7", scope: ["documents.read"]})

      results = swarm(fn -> RefreshToken.rotate(RefreshStore.ETS, t0) end)

      assert length(results) == @swarm

      # Every result is one of: the single atomic claim ({:ok,_}); a loser
      # that saw the token already claimed (:reuse_detected, which revokes
      # the family); or a loser whose read landed after the concurrent
      # revoke already deleted the row (:invalid_grant). All three are safe;
      # what must never happen is two successful claims or a surviving fork.
      assert Enum.all?(results, fn r ->
               match?({:ok, _}, r) or r in [{:error, :reuse_detected}, {:error, :invalid_grant}]
             end),
             "results must be {:ok,_}, :reuse_detected, or :invalid_grant; got #{inspect(results)}"

      winners = Enum.filter(results, &match?({:ok, _}, &1))

      assert length(winners) <= 1,
             "at most one rotation may claim a live token; got #{length(winners)}"

      # No two distinct successors both rotate. If a winner emerged, its
      # successor token must be the ONLY live token, and even it does not
      # rotate once a concurrent reuse revoked the family. Confirm forkless:
      # the original no longer rotates, and any successor is non-rotatable.
      refute match?({:ok, _}, RefreshToken.rotate(RefreshStore.ETS, t0)),
             "the claimed original must not rotate again"

      successor_tokens =
        for {:ok, %{token: tok}} <- winners, do: tok

      for tok <- successor_tokens do
        refute match?({:ok, _}, RefreshToken.rotate(RefreshStore.ETS, tok)),
               "no successor may rotate once the family is revoked (forkless invariant)"
      end
    end
  end

  describe "DPoP replay CAS: flooded verification of one proof" do
    test "exactly one parallel verify_proof of the same jti wins; the rest are :replay" do
      {proof, _jkt} = Factory.dpop_proof()

      verify = fn ->
        DPoP.verify_proof(proof,
          http_method: "POST",
          http_uri: "https://api.example.com/oauth/token",
          replay_check: &DPoP.ReplayCache.check_and_record/2
        )
      end

      results = swarm(verify)

      assert length(results) == @swarm

      winners = Enum.filter(results, &match?({:ok, _}, &1))
      replays = Enum.filter(results, &(&1 == {:error, :replay}))

      assert length(winners) == 1,
             "exactly one verify may record the jti first; got #{length(winners)}"

      assert length(replays) == @swarm - 1,
             "every other verify of the same jti must be :replay; got #{length(replays)}"

      # The sole winner carries the verified shape: same jkt/jti the others
      # collided on, proving they raced on one identity, not distinct proofs.
      [{:ok, verified}] = winners
      assert is_binary(verified.jkt)
      assert is_binary(verified.jti)
    end
  end
end
