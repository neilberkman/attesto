defmodule Attesto.GrantsConcurrencyTest do
  @moduledoc false
  # Live concurrency tests: hammer the atomic single-use / claim primitives
  # with many simultaneous redemptions/rotations of the SAME credential and
  # assert the safety invariant - at most one winner - holds. These are the
  # tests that catch a non-atomic store (the class of bug that lets a
  # captured code/token be used twice).
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.CodeStore
  alias Attesto.PKCE
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken

  @verifier "concurrency-verifier-unreserved.chars_aaaaaaaaaaaa~0"
  @racers 25

  setup do
    start_supervised!(CodeStore.ETS)
    start_supervised!(RefreshStore.ETS)
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  defp race(fun) do
    1..@racers
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(5_000)
  end

  describe "authorization code single-use under concurrency" do
    test "exactly one of many simultaneous redemptions of one code wins", %{challenge: challenge} do
      {:ok, code} =
        AuthorizationCode.issue(CodeStore.ETS, %{
          client_id: "oc_app",
          redirect_uri: "https://app.example.com/cb",
          code_challenge: challenge,
          subject: "usr_42",
          scope: ["documents.read"]
        })

      params = %{redirect_uri: "https://app.example.com/cb", code_verifier: @verifier, client_id: "oc_app"}

      results = race(fn -> AuthorizationCode.redeem(CodeStore.ETS, code, params) end)

      winners = Enum.count(results, &match?({:ok, _}, &1))
      losers = Enum.count(results, &(&1 == {:error, :invalid_grant}))

      assert winners == 1, "exactly one redemption may win; got #{winners}"
      assert losers == @racers - 1
    end
  end

  describe "refresh rotation claim under concurrency" do
    test "no two simultaneous rotations of one token both mint a successor" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", scope: ["documents.read"]})

      results = race(fn -> RefreshToken.rotate(RefreshStore.ETS, t0) end)

      winners = Enum.count(results, &match?({:ok, _}, &1))

      # The atomic claim guarantees at most one successful rotation. The
      # remaining racers see the token already claimed and report reuse,
      # which revokes the family - the conservative response to what looks
      # like a concurrent double-use of one refresh token.
      #
      # A racer that passed the initial non-consuming `get` but whose
      # `consume` call arrives after `revoke_family` has already deleted the
      # token row from ETS will see `{:error, :invalid_grant}` (the store
      # returns `:error` for an absent row). Both `:reuse_detected` and
      # `:invalid_grant` are safe terminal outcomes: neither produces a
      # successor, and the family is revoked either way.
      assert winners <= 1, "at most one rotation may claim a token; got #{winners}"

      assert Enum.all?(results, fn r ->
               match?({:ok, _}, r) or r == {:error, :reuse_detected} or r == {:error, :invalid_grant}
             end)

      # Whichever way the race resolved, the family must not be left in a
      # forked state: a fresh rotation of the original token now fails.
      refute match?({:ok, _}, RefreshToken.rotate(RefreshStore.ETS, t0))
    end
  end
end
