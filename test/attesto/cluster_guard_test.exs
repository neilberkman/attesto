defmodule Attesto.ClusterGuardTest do
  @moduledoc false
  # `assert_single_node!/2` is pure with respect to the test VM: it reads
  # `Node.list/0` and the per-store acknowledgement flag only. The test VM
  # runs single-node (`Node.list() == []`), so every assertion here is in
  # the un-clustered regime. async: true is safe: the function touches no
  # shared, named state.
  use ExUnit.Case, async: true

  alias Attesto.ClusterGuard

  # A stand-in store module name for the error/log message. It does not
  # need to exist as a real module: `assert_single_node!/2` only inspects
  # it for the message.
  alias Attesto.CodeStore.ETS

  defmodule SomeMod do
    @moduledoc false
  end

  describe "assert_single_node!/2 in an un-clustered test VM" do
    test "Node.list() is empty in this VM (precondition for the un-acknowledged path)" do
      assert Node.list() == []
    end

    test "returns :ok when acknowledged? is true regardless of cluster state" do
      assert :ok = ClusterGuard.assert_single_node!(SomeMod, true)
    end

    test "returns :ok when acknowledged? is false and there are no peers" do
      # Node.list() == [] in the test VM, so the un-acknowledged branch
      # takes the empty-peers clause and returns :ok rather than raising.
      assert :ok = ClusterGuard.assert_single_node!(SomeMod, false)
    end

    test "the acknowledged short-circuit does not consult Node.list/0" do
      # The `true` clause matches before any cluster inspection, so the
      # result is :ok independent of whatever Node.list/0 would report.
      assert :ok = ClusterGuard.assert_single_node!(__MODULE__, true)
    end
  end

  describe "the bundled ETS stores boot single-node" do
    # In this un-clustered VM the guard does not raise, so each ETS store
    # (which calls assert_single_node!/2 in init with the default
    # multi_node_acknowledged?: false) starts cleanly under the test
    # supervisor. This is the happy single-node path the guard is meant to
    # leave untouched. start_supervised! tears them down after the test.

    test "Attesto.CodeStore.ETS starts under the default (un-acknowledged) flag" do
      pid = start_supervised!(ETS)
      assert is_pid(pid)
      assert Process.alive?(pid)
    end

    test "Attesto.DPoP.NonceStore.ETS starts under the default (un-acknowledged) flag" do
      pid = start_supervised!(Attesto.DPoP.NonceStore.ETS)
      assert is_pid(pid)
      assert Process.alive?(pid)
    end
  end

  # COVERAGE NOTE: the clustered-raise branch of assert_single_node!/2
  # (Node.list/0 non-empty AND acknowledged? false -> Logger.error +
  # raise RuntimeError) is NOT exercised here. Reaching it requires a
  # second, connected BEAM node so that Node.list/0 returns a non-empty
  # peer list; a single-node ExUnit VM cannot produce that without
  # spinning up a peer (e.g. :peer / :slave) and `Node.connect/1`. That
  # is an integration concern outside this unit test. The pure logic of
  # the branch is still pinned indirectly: this test asserts Node.list()
  # == [] is the live precondition, so the false/empty path returning :ok
  # and the false/non-empty path raising are the only two possibilities,
  # and only the former is reachable in this VM.
end
