defmodule Attesto.RevocationTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Revocation
  alias Attesto.Secret

  setup do
    start_supervised!(RefreshStore.ETS)
    :ok
  end

  test "revoking a refresh token kills its whole family" do
    {:ok, %{token: r0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42"})
    {:ok, %{token: r1}} = RefreshToken.rotate(RefreshStore.ETS, r0)

    assert :ok = Revocation.revoke(RefreshStore.ETS, r1)

    # The live successor no longer rotates; the family is gone.
    assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, r1)
  end

  test "revoking an unknown token is :ok (no existence oracle)" do
    assert :ok = Revocation.revoke(RefreshStore.ETS, "never-issued")
  end

  test "revocation is idempotent" do
    {:ok, %{token: r0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42"})
    assert :ok = Revocation.revoke(RefreshStore.ETS, r0)
    assert :ok = Revocation.revoke(RefreshStore.ETS, r0)
  end

  describe "client binding" do
    test "the issuing client may revoke" do
      {:ok, %{token: r0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", client_id: "oc_a"})

      assert :ok = Revocation.revoke(RefreshStore.ETS, r0, client_id: "oc_a")
    end

    test "a different client is :unauthorized_client and does not revoke" do
      {:ok, %{token: r0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", client_id: "oc_a"})

      assert {:error, :unauthorized_client} =
               Revocation.revoke(RefreshStore.ETS, r0, client_id: "oc_b")

      # Not revoked: the legitimate client can still rotate it.
      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, r0, client_id: "oc_a")
    end

    test "omitting the client on a client-bound token is fail-closed" do
      {:ok, %{token: r0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", client_id: "oc_a"})

      assert {:error, :unauthorized_client} = Revocation.revoke(RefreshStore.ETS, r0)
    end

    test "allow_missing_client_id? opts out of the client check" do
      {:ok, %{token: r0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", client_id: "oc_a"})

      assert :ok = Revocation.revoke(RefreshStore.ETS, r0, allow_missing_client_id?: true)
    end

    test "an unbound token revokes without a presented client" do
      {:ok, %{token: r0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42"})
      assert :ok = Revocation.revoke(RefreshStore.ETS, r0)
    end
  end

  describe "expired record is not an existence oracle" do
    # RFC 7009 §2.2 / §2.1: an expired refresh token that lingers in the
    # store must be indistinguishable from a never-issued one. Returning
    # :unauthorized_client for a wrong/missing client on an EXPIRED record
    # would leak that the token once existed, so an expired record is
    # treated as absent: :ok, no client check.
    setup do
      token = "expired-bound-token"

      :ok =
        RefreshStore.ETS.insert(%{
          token_hash: Secret.hash(token),
          family_id: "fam-expired",
          generation: 0,
          data: %{client_id: "oc_a"},
          # one second in the past
          expires_at: System.system_time(:second) - 1,
          consumed: false
        })

      {:ok, token: token}
    end

    test "a wrong client on an expired bound token is :ok, not :unauthorized_client", %{token: token} do
      assert :ok = Revocation.revoke(RefreshStore.ETS, token, client_id: "oc_b")
    end

    test "a missing client on an expired bound token is :ok, not fail-closed", %{token: token} do
      assert :ok = Revocation.revoke(RefreshStore.ETS, token)
    end
  end
end
