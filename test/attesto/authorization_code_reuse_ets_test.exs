defmodule Attesto.AuthorizationCodeReuseETSTest do
  @moduledoc false
  # The ETS reference CodeStore does NOT implement the optional reuse-tracking
  # callbacks, so a re-presentation surfaces as plain invalid_grant rather than
  # {:error, {:reuse, meta}}. (The reuse-tracking path is covered by the
  # per-test Agent store in authorization_code_reuse_test.exs.)
  #
  # async: false - `Attesto.CodeStore.ETS` is a named singleton; running this
  # concurrently with any other test that boots the same named store races on
  # shared state.
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore.ETS
  alias Attesto.PKCE

  @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"
  @redirect_uri "https://app.example.com/cb"
  @client_id "oc_app"
  @subject "usr_42"
  @scope ["documents.read"]
  @family_id "fam_abc123"

  setup do
    start_supervised!(ETS)
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  defp code_attrs(challenge, overrides \\ %{}) do
    Map.merge(
      %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        scope: @scope,
        subject: @subject
      },
      overrides
    )
  end

  defp redeem_params(overrides \\ %{}) do
    Map.merge(%{redirect_uri: @redirect_uri, code_verifier: @verifier, client_id: @client_id}, overrides)
  end

  describe "redeem/4 without reuse tracking (ETS reference store)" do
    test "a second redeem is invalid_grant: the store does not track reuse", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(ETS, code_attrs(challenge, %{family_id: @family_id}))

      # family_id still round-trips even when reuse tracking is absent.
      assert {:ok, %Grant{family_id: @family_id}} = AuthorizationCode.redeem(ETS, code, redeem_params())

      # A store without mark_consumed/2 surfaces a re-presentation as plain
      # invalid_grant - reuse detection is additive, never required.
      refute function_exported?(ETS, :mark_consumed, 2)
      assert {:error, :invalid_grant} = AuthorizationCode.redeem(ETS, code, redeem_params())
    end
  end
end
