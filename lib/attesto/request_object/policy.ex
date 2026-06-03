defmodule Attesto.RequestObject.Policy do
  @moduledoc """
  Verification policy for signed authorization request objects (JAR, RFC 9101).

  Policy expressed as data the caller passes to
  `Attesto.AuthorizationRequest.validate/2`, which threads it into
  `Attesto.RequestObject.verify/3`. The default `%Policy{}` is the generic
  OpenID Connect §6.1 / RFC 9101 baseline (a signed request object is verified,
  but `nbf`/`exp`/`typ` are not required). The FAPI 2.0 Message Signing §5.3.1
  profile is the named `fapi_message_signing/0` constructor - profile data, not
  a feature flag and not a backwards-compatibility shim.
  """

  alias Attesto.SigningAlg

  @type t :: %__MODULE__{
          accepted_algs: [SigningAlg.alg()] | nil,
          require_nbf: boolean(),
          max_nbf_age_seconds: pos_integer() | nil,
          require_exp: boolean(),
          max_lifetime_seconds: pos_integer() | nil,
          accepted_typ: [String.t() | nil] | nil
        }

  defstruct accepted_algs: nil,
            require_nbf: false,
            max_nbf_age_seconds: nil,
            require_exp: false,
            max_lifetime_seconds: nil,
            accepted_typ: nil

  @doc """
  The generic OpenID Connect §6.1 / RFC 9101 baseline: a signed request object
  is verified, but `nbf`/`exp`/`typ` are not required. Equivalent to `%Policy{}`.
  """
  @spec generic() :: t()
  def generic, do: %__MODULE__{}

  @doc """
  The FAPI 2.0 Message Signing §5.3.1 profile for signed request objects:

    * `nbf` REQUIRED, no more than 60 minutes in the past;
    * `exp` REQUIRED, no more than 60 minutes after `nbf`;
    * JOSE header `typ` must be `"oauth-authz-req+jwt"`.

  `accepted_algs` is left `nil` to inherit `Attesto.RequestObject.verify/3`'s
  default (`Attesto.SigningAlg.fapi_algs/0`: PS256, ES256, EdDSA).

  Note: pinning `typ` to exactly `"oauth-authz-req+jwt"` (rejecting an absent or
  other `typ`) is stricter than §5.3.1's literal "shall accept that typ"; it is
  the RFC 9101 §10.8 explicit-typing defence against cross-JWT confusion, and is
  what the FAPI conformance suite exercises. A deployment wanting the softer
  reading can build a `%Policy{}` with `accepted_typ: ["oauth-authz-req+jwt", nil]`.
  """
  @spec fapi_message_signing() :: t()
  def fapi_message_signing do
    %__MODULE__{
      require_nbf: true,
      max_nbf_age_seconds: 3600,
      require_exp: true,
      max_lifetime_seconds: 3600,
      accepted_typ: ["oauth-authz-req+jwt"]
    }
  end

  @doc """
  Flatten the policy to `Attesto.RequestObject.verify/3` options, dropping `nil`
  values so `verify/3` keeps its own defaults (notably `accepted_algs`, which
  defaults to `Attesto.SigningAlg.fapi_algs/0`).
  """
  @spec to_verify_opts(t()) :: keyword()
  def to_verify_opts(%__MODULE__{} = policy) do
    policy
    |> Map.from_struct()
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Keyword.new()
  end
end
