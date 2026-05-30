defmodule Attesto.SecretTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Secret
  alias Attesto.Thumbprint

  @base64url_chars ~r/\A[A-Za-z0-9_-]+\z/

  describe "generate/1" do
    test "returns a base64url-no-pad string with only alphabet characters" do
      secret = Secret.generate()

      assert is_binary(secret)
      assert Regex.match?(@base64url_chars, secret)
      refute String.contains?(secret, "=")
      refute String.contains?(secret, "+")
      refute String.contains?(secret, "/")
    end

    test "default 32 bytes encodes to 43 characters" do
      assert String.length(Secret.generate()) == 43
      assert String.length(Secret.generate(32)) == 43
    end

    test "a different byte count changes the encoded length" do
      # 16 bytes -> 22 base64url-no-pad chars, 64 bytes -> 86.
      assert String.length(Secret.generate(16)) == 22
      assert String.length(Secret.generate(64)) == 86

      refute String.length(Secret.generate(16)) == String.length(Secret.generate(32))
    end

    test "two generated secrets differ (uniqueness)" do
      secrets = for _ <- 1..100, do: Secret.generate()

      assert length(Enum.uniq(secrets)) == 100
    end

    test "every character is drawn from the base64url alphabet across many samples" do
      for _ <- 1..50 do
        secret = Secret.generate()
        assert Regex.match?(@base64url_chars, secret)
      end
    end
  end

  describe "hash/1" do
    test "is deterministic for the same input" do
      input = "the-quick-brown-fox"

      assert Secret.hash(input) == Secret.hash(input)
    end

    test "differs for different inputs" do
      refute Secret.hash("alpha") == Secret.hash("beta")
    end

    test "equals Attesto.Thumbprint.of/1 of the same input" do
      input = Secret.generate()

      assert Secret.hash(input) == Thumbprint.of(input)
    end

    test "is a canonical 43-character thumbprint value" do
      hash = Secret.hash(Secret.generate())

      assert String.length(hash) == 43
      assert Thumbprint.valid?(hash)
    end
  end
end
