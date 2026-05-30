defmodule Attesto.PrincipalKind do
  @moduledoc """
  One kind of subject a token can describe.

  A single issuer and verifier can serve several kinds of principal - a
  machine client authenticating with `client_credentials`, a human whose
  dashboard session was exchanged for a token, a device. They share every
  standard claim (`iss`, `aud`, `exp`, `sub`, `scope`, …) and differ only
  in three policy-defined ways, which this struct captures:

    * **`claim_value`** - the value carried in the configured principal-kind
      claim (see `Attesto.Config`). A token's kind is read from this claim
      and cross-checked, so a token can never be silently routed down the
      wrong principal path.

    * **`sub_prefix`** - the namespace prefix the `sub` claim MUST carry
      for this kind (e.g. `"oc_"` for a client, `"usr_"` for a user). The
      verifier requires `sub` to start with the prefix of the kind named
      in the principal-kind claim; a mismatch fails verification. This is
      defense-in-depth against a token whose kind claim and subject
      disagree.

    * **`required_claims`** - extra claims this kind MUST carry, each with
      a shape. A client carries `client_id`; a user-session token might
      carry an acting-account id, a session id, and a token-version
      counter for bulk revocation. The verifier (and the minter) reject a
      token of this kind that is missing one, or whose value has the wrong
      shape, so downstream code never branches on a `nil` it assumed was
      present.

  Attesto does not interpret what a kind *means* - it only enforces the
  cross-checks. The meaning is the host application's policy.

  ## Required-claim shapes

  Each entry in `required_claims` is `{claim_name, shape}` where `shape`
  is one of:

    * `:non_empty_string` - a binary that is not `""`.
    * `:string` - any binary (may be empty).
    * `:non_neg_integer` - an integer `>= 0`.

  """

  @enforce_keys [:claim_value, :sub_prefix]
  defstruct claim_value: nil, sub_prefix: nil, required_claims: []

  @type shape :: :non_empty_string | :string | :non_neg_integer

  @type t :: %__MODULE__{
          claim_value: String.t(),
          sub_prefix: String.t(),
          required_claims: [{String.t(), shape()}]
        }

  @valid_shapes [:non_empty_string, :string, :non_neg_integer]

  @doc """
  Build a principal kind.

      Attesto.PrincipalKind.new("client", "oc_",
        required_claims: [{"client_id", :non_empty_string}]
      )

  Raises `ArgumentError` if `claim_value`/`sub_prefix` are not non-empty
  binaries or any required-claim shape is unknown - this is configuration,
  evaluated once at boot, so a malformed kind should fail loudly rather
  than at the first token operation.
  """
  @spec new(String.t(), String.t(), keyword()) :: t()
  def new(claim_value, sub_prefix, opts \\ []) do
    required_claims = Keyword.get(opts, :required_claims, [])

    validate_binary!(:claim_value, claim_value)
    validate_binary!(:sub_prefix, sub_prefix)
    validate_required_claims!(required_claims)

    %__MODULE__{
      claim_value: claim_value,
      sub_prefix: sub_prefix,
      required_claims: required_claims
    }
  end

  @doc """
  Returns `:ok` if `claims` carries every required claim for this kind
  with the correct shape, or `{:error, {claim_name, :missing | :wrong_shape}}`
  on the first violation.
  """
  @spec check_required(t(), %{optional(String.t()) => term()}) ::
          :ok | {:error, {String.t(), :missing | :wrong_shape}}
  def check_required(%__MODULE__{required_claims: required}, claims) when is_map(claims) do
    Enum.reduce_while(required, :ok, fn {name, shape}, :ok ->
      case Map.fetch(claims, name) do
        :error -> {:halt, {:error, {name, :missing}}}
        {:ok, value} -> check_one(name, shape, value)
      end
    end)
  end

  defp check_one(name, shape, value) do
    if shape_ok?(shape, value), do: {:cont, :ok}, else: {:halt, {:error, {name, :wrong_shape}}}
  end

  @doc false
  @spec shape_ok?(shape(), term()) :: boolean()
  def shape_ok?(:non_empty_string, v), do: is_binary(v) and v != ""
  def shape_ok?(:string, v), do: is_binary(v)
  def shape_ok?(:non_neg_integer, v), do: is_integer(v) and v >= 0

  defp validate_binary!(field, value) do
    if !(is_binary(value) and value != "") do
      raise ArgumentError,
            "Attesto.PrincipalKind #{field} must be a non-empty string; got #{inspect(value)}"
    end
  end

  defp validate_required_claims!(required) when is_list(required) do
    Enum.each(required, fn
      {name, shape} when is_binary(name) and shape in @valid_shapes ->
        :ok

      other ->
        raise ArgumentError,
              "Attesto.PrincipalKind required_claims entries must be " <>
                "{claim_name :: String.t(), shape} where shape is one of " <>
                "#{inspect(@valid_shapes)}; got #{inspect(other)}"
    end)
  end

  defp validate_required_claims!(other) do
    raise ArgumentError,
          "Attesto.PrincipalKind :required_claims must be a list; got #{inspect(other)}"
  end
end
