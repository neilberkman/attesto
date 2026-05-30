defmodule Attesto.SecureCompareTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.SecureCompare

  test "equal binaries compare true" do
    assert SecureCompare.equal?("abc123", "abc123")
    assert SecureCompare.equal?("", "")
  end

  test "different binaries of the same length compare false" do
    refute SecureCompare.equal?("abc123", "abc124")
  end

  test "binaries of different lengths compare false (no raise)" do
    refute SecureCompare.equal?("abc", "abcd")
    refute SecureCompare.equal?("abcd", "abc")
  end

  test "non-binary operands compare false" do
    refute SecureCompare.equal?("abc", nil)
    refute SecureCompare.equal?(:abc, "abc")
    refute SecureCompare.equal?(123, 123)
  end
end
