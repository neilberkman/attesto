defmodule Attesto.RequestObject.PolicyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.RequestObject.Policy

  describe "to_verify_opts/1" do
    test "generic/0 materializes no strict opts (only the false require flags)" do
      opts = Policy.to_verify_opts(Policy.generic())

      # nils are dropped so RequestObject.verify/3 keeps its own defaults
      # (notably :accepted_algs -> SigningAlg.fapi_algs()).
      refute Keyword.has_key?(opts, :accepted_algs)
      refute Keyword.has_key?(opts, :max_nbf_age_seconds)
      refute Keyword.has_key?(opts, :max_lifetime_seconds)
      refute Keyword.has_key?(opts, :accepted_typ)
      assert Keyword.get(opts, :require_nbf) == false
      assert Keyword.get(opts, :require_exp) == false
    end

    test "fapi_message_signing/0 materializes the FAPI 2.0 §5.3.1 opts" do
      opts = Policy.to_verify_opts(Policy.fapi_message_signing())

      assert Keyword.get(opts, :require_nbf) == true
      assert Keyword.get(opts, :max_nbf_age_seconds) == 3600
      assert Keyword.get(opts, :require_exp) == true
      assert Keyword.get(opts, :max_lifetime_seconds) == 3600
      assert Keyword.get(opts, :accepted_typ) == ["oauth-authz-req+jwt"]
      # accepted_algs is left nil so verify/3's fapi_algs() default applies.
      refute Keyword.has_key?(opts, :accepted_algs)
    end

    test "generic/0 equals the struct default" do
      assert Policy.generic() == %Policy{}
    end
  end
end
