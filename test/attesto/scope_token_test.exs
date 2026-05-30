defmodule Attesto.ScopeTokenTest do
  @moduledoc false
  # The RFC 6749 Appendix A scope-token ABNF (`1*NQCHAR`, NQCHAR =
  # %x21 / %x23-5B / %x5D-7E - printable ASCII minus space, double-quote,
  # backslash) at every boundary. First the pure `Scope.valid_token?/1`
  # predicate, then the three issuance surfaces that lean on it
  # (`Token.mint`, `AuthorizationCode.issue`, `RefreshToken.issue`), and
  # finally a round-trip proving the `scope` claim is a single opaque
  # string on the wire that `verify/3` never re-splits.
  #
  # Anything that installs a keystore via Factory.config or starts a
  # named-singleton store forces serial execution, so the whole module is
  # async: false.
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.CodeStore
  alias Attesto.PKCE
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Scope
  alias Attesto.Test.Factory
  alias Attesto.Token

  # A representative ABNF-violating scope token for each forbidden class.
  # Each, embedded space-joined into a `scope` claim, would be misread
  # downstream (a space splits one grant into two; a control char or a
  # non-ASCII byte is simply outside the grammar). Keyed by a label used in
  # the per-surface generated cases.
  @bad_tokens %{
    "empty string" => "",
    "embedded space" => "read write",
    "tab" => "read\twrite",
    "carriage-return/line-feed" => "read\r\nwrite",
    "double-quote" => "read\"write",
    "backslash" => "read\\write",
    "non-ASCII (latin-1)" => "réad",
    "non-ASCII (multibyte)" => "documents.a, читать",
    "control char (NUL)" => "read\0write",
    "control char (DEL)" => "read\x7Fwrite"
  }

  describe "Scope.valid_token?/1 - ABNF acceptance" do
    test "a single printable-ASCII token is valid" do
      assert Scope.valid_token?("read")
    end

    test "a dotted resource.action token is valid" do
      assert Scope.valid_token?("documents.read")
      assert Scope.valid_token?("webhooks.write")
    end

    test "the resource-level wildcard grant form is a valid token (no space)" do
      assert Scope.valid_token?("documents.*")
    end

    test "the full wildcard is a valid token (single printable char)" do
      assert Scope.valid_token?("*")
    end

    test "every printable-ASCII char except space/quote/backslash is accepted" do
      # NQCHAR = %x21 / %x23-5B / %x5D-7E. Walk the whole printable range
      # and assert each single-char token is valid exactly when it is an
      # NQCHAR, so the regex boundaries (0x21..0x7E minus 0x20/0x22/0x5C)
      # are pinned precisely.
      for codepoint <- 0x21..0x7E do
        char = <<codepoint::utf8>>
        nqchar? = codepoint not in [0x22, 0x5C]

        assert Scope.valid_token?(char) == nqchar?,
               "codepoint 0x#{Integer.to_string(codepoint, 16)} (#{inspect(char)}) " <>
                 "expected valid?=#{nqchar?}"
      end
    end
  end

  describe "Scope.valid_token?/1 - ABNF rejection" do
    test "the empty string is not a valid token (ABNF requires 1*NQCHAR)" do
      refute Scope.valid_token?("")
    end

    test "a token with an embedded space is rejected" do
      # `read write` would, joined into a space-delimited scope claim, be
      # indistinguishable from two separate grants.
      refute Scope.valid_token?("read write")
      refute Scope.valid_token?(" read")
      refute Scope.valid_token?("read ")
    end

    test "a tab is rejected" do
      refute Scope.valid_token?("read\twrite")
    end

    test "a carriage return or line feed is rejected" do
      refute Scope.valid_token?("read\rwrite")
      refute Scope.valid_token?("read\nwrite")
      refute Scope.valid_token?("read\r\nwrite")
    end

    test "a double-quote is rejected (excluded from NQCHAR)" do
      refute Scope.valid_token?("read\"write")
      refute Scope.valid_token?("\"")
    end

    test "a backslash is rejected (excluded from NQCHAR)" do
      refute Scope.valid_token?("read\\write")
      refute Scope.valid_token?("\\")
    end

    test "a non-ASCII character is rejected (NQCHAR caps at 0x7E)" do
      refute Scope.valid_token?("réad")
      refute Scope.valid_token?("документы.read")
      # A lone high byte (0x80) and beyond.
      refute Scope.valid_token?(<<0x80>>)
      refute Scope.valid_token?(<<0xC3, 0xA9>>)
    end

    test "a control character is rejected (below 0x21)" do
      refute Scope.valid_token?("read\0write")
      refute Scope.valid_token?("read\x01write")
      refute Scope.valid_token?("read\x1Fwrite")
      refute Scope.valid_token?("read\x7Fwrite")
    end

    test "non-binary inputs are rejected without raising" do
      refute Scope.valid_token?(nil)
      refute Scope.valid_token?(:read)
      refute Scope.valid_token?(123)
      refute Scope.valid_token?(["read"])
    end
  end

  describe "Token.mint/3 rejects ABNF-invalid scopes as :invalid_scopes" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      {:ok, config: config}
    end

    defp client_principal(scopes) do
      %{
        kind: "client",
        sub: "oc_abc123",
        scopes: scopes,
        claims: %{"client_id" => "oc_abc123"}
      }
    end

    test "a list of valid scope tokens mints", %{config: config} do
      assert {:ok, %{access_token: jwt, scope: scope_string}} =
               Token.mint(config, client_principal(["documents.read", "positions.read"]))

      assert is_binary(jwt)
      assert scope_string == "documents.read positions.read"
    end

    for {label, bad} <- @bad_tokens do
      test "rejects #{label} mixed into the scope list", %{config: config} do
        assert {:error, :invalid_scopes} =
                 Token.mint(config, client_principal(["documents.read", unquote(bad)]))
      end

      test "rejects #{label} as the sole scope", %{config: config} do
        assert {:error, :invalid_scopes} =
                 Token.mint(config, client_principal([unquote(bad)]))
      end
    end

    test "a non-list scopes value is :invalid_scopes (not a crash)", %{config: config} do
      assert {:error, :invalid_scopes} =
               Token.mint(config, %{
                 kind: "client",
                 sub: "oc_abc123",
                 scopes: "documents.read",
                 claims: %{"client_id" => "oc_abc123"}
               })
    end
  end

  describe "AuthorizationCode.issue/3 rejects ABNF-invalid scopes as :invalid_scope" do
    @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"
    @redirect_uri "https://app.example.com/cb"
    @client_id "oc_app"
    @subject "usr_42"

    setup do
      start_supervised!(CodeStore.ETS)
      {:ok, challenge} = PKCE.challenge(@verifier)
      %{challenge: challenge}
    end

    defp code_attrs(challenge, scope) do
      %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: @subject,
        scope: scope
      }
    end

    test "a list of valid scope tokens issues a code", %{challenge: challenge} do
      assert {:ok, code} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, ["documents.read"]))

      assert is_binary(code) and code != ""
    end

    for {label, bad} <- @bad_tokens do
      test "rejects #{label} mixed into the scope list", %{challenge: challenge} do
        assert {:error, :invalid_scope} =
                 AuthorizationCode.issue(
                   CodeStore.ETS,
                   code_attrs(challenge, ["documents.read", unquote(bad)])
                 )
      end
    end
  end

  describe "RefreshToken.issue/3 rejects ABNF-invalid scopes as :invalid_scope" do
    setup do
      start_supervised!(RefreshStore.ETS)
      :ok
    end

    defp refresh_context(scope) do
      %{subject: "usr_42", scope: scope}
    end

    test "a list of valid scope tokens issues a refresh token" do
      assert {:ok, %{token: token}} =
               RefreshToken.issue(RefreshStore.ETS, refresh_context(["documents.read"]))

      assert is_binary(token) and token != ""
    end

    for {label, bad} <- @bad_tokens do
      test "rejects #{label} mixed into the scope list" do
        assert {:error, :invalid_scope} =
                 RefreshToken.issue(
                   RefreshStore.ETS,
                   refresh_context(["documents.read", unquote(bad)])
                 )
      end
    end
  end

  describe "verify/3 treats `scope` as one opaque string and never re-splits it" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      {:ok, config: config}
    end

    test "a token minted from valid tokens round-trips with a space-joined scope claim",
         %{config: config} do
      # mint refuses an ambiguous (space-bearing) scope token up front, so a
      # token can only ever reach the wire with a `scope` claim built from
      # individually-valid tokens. The multi-grant claim is one string on
      # the wire: `verify/3` returns it verbatim and does NOT re-split or
      # re-validate the tokens. Scope *enforcement* is the resource server's
      # job over this string; Attesto only guarantees the string is
      # unambiguous because every token was validated at mint.
      assert {:ok, %{access_token: jwt, scope: scope_string}} =
               Token.mint(config, client_principal(["documents.read", "positions.read"]))

      assert scope_string == "documents.read positions.read"

      assert {:ok, claims} = Token.verify(config, jwt)
      assert claims["scope"] == "documents.read positions.read"
      # The claim is a single binary, not a list - the space delimiter is
      # only meaningful once the resource server chooses to split it.
      assert is_binary(claims["scope"])
    end

    test "a single-scope token round-trips unchanged", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(config, client_principal(["documents.read"]))

      assert {:ok, %{"scope" => "documents.read"}} = Token.verify(config, jwt)
    end

    test "an empty scope list mints and verifies as an empty scope string",
         %{config: config} do
      # An empty grant set is legal (`Enum.all?([])` is true); the join is
      # the empty string. verify echoes it back; `scope` being a (possibly
      # empty) string is the only shape requirement.
      assert {:ok, %{access_token: jwt, scope: ""}} =
               Token.mint(config, client_principal([]))

      assert {:ok, %{"scope" => ""}} = Token.verify(config, jwt)
    end

    test "duplicate scope tokens are de-duplicated before the join", %{config: config} do
      # normalize_scopes/1 runs Enum.uniq, so a doubled grant collapses to
      # one token in the claim - it never produces a `read read` ambiguity.
      assert {:ok, %{scope: "documents.read"}} =
               Token.mint(config, client_principal(["documents.read", "documents.read"]))
    end
  end
end
