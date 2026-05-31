defmodule Attesto.RefreshTokenTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Secret

  setup do
    start_supervised!(RefreshStore.ETS)
    :ok
  end

  # A valid DPoP key thumbprint: Secret.hash/1 yields the canonical
  # 43-char base64url SHA-256 digest that Thumbprint.valid?/1 accepts.
  defp jkt(seed), do: Secret.hash(seed)

  # No client_id by default, so tokens are unbound and rotation needs no
  # presenting client (client binding is fail-closed and exercised on its
  # own in grants_client_scope_test). Tests that care add :client_id.
  defp context(overrides \\ %{}) do
    Map.merge(%{subject: "usr_42", scope: ["documents.read"]}, overrides)
  end

  describe "issue/3" do
    test "success returns a token, a family_id, and generation 0" do
      assert {:ok, %{token: token, family_id: family_id, generation: 0}} =
               RefreshToken.issue(RefreshStore.ETS, context())

      assert is_binary(token) and token != ""
      assert is_binary(family_id) and family_id != ""
    end

    test "a missing or empty subject is rejected as invalid_subject" do
      assert {:error, :invalid_subject} =
               RefreshToken.issue(RefreshStore.ETS, %{scope: ["documents.read"]})

      assert {:error, :invalid_subject} =
               RefreshToken.issue(RefreshStore.ETS, %{subject: ""})
    end

    test "a non-string-list scope is rejected as invalid_scope" do
      assert {:error, :invalid_scope} =
               RefreshToken.issue(RefreshStore.ETS, context(%{scope: ["documents.read", :nope]}))

      assert {:error, :invalid_scope} =
               RefreshToken.issue(RefreshStore.ETS, context(%{scope: "documents.read"}))
    end

    test "a malformed dpop_jkt is rejected as invalid_dpop_jkt" do
      assert {:error, :invalid_dpop_jkt} =
               RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: "not-a-valid-thumbprint"}))
    end

    test "a non-map :claims is rejected as invalid_claims" do
      # :claims is opaque host context, documented as a map and stored
      # verbatim; a non-map (here a list) is rejected at the issue boundary.
      assert {:error, :invalid_claims} =
               RefreshToken.issue(RefreshStore.ETS, context(%{claims: [:not, :a, :map]}))
    end

    test "a fresh issue starts a NEW family (distinct family_id across two issues)" do
      {:ok, %{family_id: fam_a, generation: 0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, %{family_id: fam_b, generation: 0}} = RefreshToken.issue(RefreshStore.ETS, context())

      refute fam_a == fam_b
    end

    test "ttl and now are honored: a token issued in the past is already expired at rotate" do
      {:ok, %{token: token}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 100, now: 1_000)

      # now (2_000) is past expires_at (1_000 + 100 = 1_100).
      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, token, now: 2_000)
    end

    test "ttl and now: a token is still live just before its expiry boundary" do
      {:ok, %{token: token}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 100, now: 1_000)

      # expires_at = 1_100; check is strict (expires_at > now), so 1_099 is live.
      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, token, now: 1_099)
    end
  end

  describe "rotate/3 success and chaining" do
    test "rotate consumes the old token and returns a generation+1 successor in the SAME family with the round-tripped context" do
      {:ok, %{token: t0, family_id: fam, generation: 0}} =
        RefreshToken.issue(RefreshStore.ETS, context(%{client_id: "oc_app"}))

      assert {:ok, %{token: t1, family_id: ^fam, generation: 1, context: ctx}} =
               RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_app")

      refute t1 == t0
      assert ctx.subject == "usr_42"
      assert ctx.scope == ["documents.read"]
      assert ctx.client_id == "oc_app"
    end

    test "an immediate honest retry of the old token returns the same successor" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, first} = RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:ok, retry} = RefreshToken.rotate(RefreshStore.ETS, t0)
      assert retry.token == first.token
      assert retry.family_id == first.family_id
      assert retry.generation == first.generation
      assert retry.context == first.context
    end

    test "an unknown token is invalid_grant" do
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, "no-such-token")
    end

    test "an expired token is rejected as expired" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 1, now: 1_000)

      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 5_000)
    end

    test "a multi-generation chain rotates 1 -> 2 -> 3 in the same family" do
      {:ok, %{token: t0, family_id: fam, generation: 0}} =
        RefreshToken.issue(RefreshStore.ETS, context())

      assert {:ok, %{token: t1, family_id: ^fam, generation: 1}} =
               RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:ok, %{token: t2, family_id: ^fam, generation: 2}} =
               RefreshToken.rotate(RefreshStore.ETS, t1)

      assert {:ok, %{token: t3, family_id: ^fam, generation: 3}} =
               RefreshToken.rotate(RefreshStore.ETS, t2)

      refute t3 in [t0, t1, t2]
    end
  end

  describe "rotate/3 reuse detection and family revocation" do
    test "strict mode keeps immediate replay as reuse detection" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, rotation_grace_seconds: 0)

      # The whole family was revoked, so the live successor no longer exists.
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1)
    end

    test "after the grace window, replaying an old generation revokes the whole family" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)
      {:ok, %{token: t2}} = RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_001)
      {:ok, %{token: t3}} = RefreshToken.rotate(RefreshStore.ETS, t2, now: 1_002)

      # Replay a stale mid-chain token (t1, already consumed by the t1->t2 rotation).
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_100)

      # Every token in the family is now gone, including the live leaf t3
      # and the already-consumed earlier generations.
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t3)
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t2)
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "a consumed-token retry with a different client revokes the family" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{client_id: "client-a"}))
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "client-a")

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "client-b")

      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1, client_id: "client-a")
    end

    test "a consumed-token retry with a different requested scope revokes the family" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, context(%{scope: ["documents.read", "documents.write"]}))

      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, scope: ["documents.read"])

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, scope: ["documents.write"])

      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1)
    end
  end

  describe "rotate/3 DPoP binding matrix" do
    test "unbound token + no presented jkt is OK" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "unbound token + a presented jkt -> :dpop_proof_unexpected" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())

      assert {:error, :dpop_proof_unexpected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: jkt("presented-key"))
    end

    test "bound token + no presented jkt -> :dpop_proof_required" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:error, :dpop_proof_required} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "bound token + matching jkt is OK" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: bound)
    end

    test "bound token + a different jkt -> :dpop_binding_mismatch" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:error, :dpop_binding_mismatch} =
               RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: jkt("other-key"))
    end
  end

  describe "rotate/3 does not burn a token on a recoverable failure" do
    # Recoverable validation (expiry, DPoP) runs on a non-consuming read
    # BEFORE the token is claimed, so a transient client error does not
    # spend the token or trip reuse detection. A corrected retry succeeds.
    test "a recoverable :dpop_proof_required leaves the token intact; the corrected retry succeeds" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      # Client forgets the proof: recoverable validation error.
      assert {:error, :dpop_proof_required} = RefreshToken.rotate(RefreshStore.ETS, t0)

      # Client retries the SAME token with the correct proof and rotates
      # cleanly: the token was never consumed, so this is not reuse.
      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: bound)
    end

    test "a recoverable :dpop_binding_mismatch leaves the token intact; the corrected retry succeeds" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:error, :dpop_binding_mismatch} =
               RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: jkt("wrong-key"))

      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: bound)
    end

    test "a recoverable :expired keeps reporting :expired, never reuse" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 1, now: 1_000)

      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 5_000)

      # Re-presenting the same token still reads as :expired, not :reuse_detected,
      # because the failed rotation never consumed it.
      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 5_000)
    end
  end
end
