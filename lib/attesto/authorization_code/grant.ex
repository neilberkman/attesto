defmodule Attesto.AuthorizationCode.Grant do
  @moduledoc """
  The validated context a successfully redeemed authorization code yields.

  `Attesto.AuthorizationCode.redeem/4` returns this struct once the code's
  expiry, redirect URI, PKCE verifier, and DPoP binding have all checked
  out. The host reads it to mint the access token (and, if it issues one,
  the refresh token): `subject` and `scope` become the token's `sub` and
  `scope`, `dpop_jkt` (when present) becomes the access token's `cnf.jkt`,
  and `claims` carries any host context that rode along from the
  authorization request.
  """

  @enforce_keys [:client_id, :redirect_uri, :subject]
  defstruct [:client_id, :redirect_uri, :subject, :dpop_jkt, scope: [], claims: %{}]

  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          subject: String.t(),
          scope: [String.t()],
          dpop_jkt: String.t() | nil,
          claims: map()
        }

  @doc false
  @spec from_data(map()) :: t()
  def from_data(data) do
    %__MODULE__{
      client_id: data.client_id,
      redirect_uri: data.redirect_uri,
      subject: data.subject,
      scope: Map.get(data, :scope, []),
      dpop_jkt: Map.get(data, :dpop_jkt),
      claims: Map.get(data, :claims, %{})
    }
  end
end
