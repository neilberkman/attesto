defmodule Attesto.RefreshStore.ETSTest do
  @moduledoc false
  # Contract tests for the single-node ETS implementation of
  # `Attesto.RefreshStore`, focused on the atomic compare-and-set in
  # consume/1 and on family revocation. The named-singleton store forces
  # async: false.
  use ExUnit.Case, async: false

  alias Attesto.RefreshStore.ETS

  setup do
    start_supervised!(ETS)
    :ok
  end

  defp record(token_hash, opts \\ []) do
    %{
      token_hash: token_hash,
      family_id: Keyword.get(opts, :family_id, "fam-default"),
      generation: Keyword.get(opts, :generation, 0),
      data: Keyword.get(opts, :data, %{subject: "usr_42", scope: ["documents.read"]}),
      expires_at: Keyword.get(opts, :expires_at, System.system_time(:second) + 1_209_600),
      consumed: Keyword.get(opts, :consumed, false)
    }
  end

  test "insert then consume returns {:ok, record} and marks it consumed" do
    rec = record("tok-consume-once")
    assert :ok = ETS.insert(rec)

    # consume returns the record as it was (unconsumed) on the winning call.
    assert {:ok, returned} = ETS.consume("tok-consume-once")
    assert returned.token_hash == "tok-consume-once"
    assert returned.consumed == false

    # A second consume must now see it consumed: the mark stuck.
    assert {:reuse, reused} = ETS.consume("tok-consume-once")
    assert reused.consumed == true
  end

  test "a second consume of the same hash returns {:reuse, record} (atomic compare-and-set)" do
    rec = record("tok-reuse")
    assert :ok = ETS.insert(rec)

    assert {:ok, _} = ETS.consume("tok-reuse")
    assert {:reuse, reused} = ETS.consume("tok-reuse")
    assert reused.token_hash == "tok-reuse"
    assert reused.family_id == "fam-default"
    assert reused.consumed == true
  end

  test "consume of an absent hash returns :error" do
    assert :error = ETS.consume("tok-never-inserted")
  end

  test "revoke_family removes every record sharing a family_id, leaving others" do
    assert :ok = ETS.insert(record("tok-fam1-a", family_id: "fam-1", generation: 0))
    assert :ok = ETS.insert(record("tok-fam1-b", family_id: "fam-1", generation: 1))
    assert :ok = ETS.insert(record("tok-fam1-c", family_id: "fam-1", generation: 2))
    assert :ok = ETS.insert(record("tok-fam2-a", family_id: "fam-2", generation: 0))

    assert :ok = ETS.revoke_family("fam-1")

    # Every fam-1 token is gone (consume sees no such token).
    assert :error = ETS.consume("tok-fam1-a")
    assert :error = ETS.consume("tok-fam1-b")
    assert :error = ETS.consume("tok-fam1-c")

    # The token in the untouched family survives and is still consumable.
    assert {:ok, survivor} = ETS.consume("tok-fam2-a")
    assert survivor.family_id == "fam-2"
  end

  test "reset clears all stored records" do
    assert :ok = ETS.insert(record("tok-r1", family_id: "fam-x"))
    assert :ok = ETS.insert(record("tok-r2", family_id: "fam-y"))

    assert :ok = ETS.reset()

    assert :error = ETS.consume("tok-r1")
    assert :error = ETS.consume("tok-r2")
  end
end
