defmodule Attesto.Keystore do
  @moduledoc """
  The behaviour Attesto uses to obtain signing and verification keys.

  A keystore answers two questions:

    * **What key do we sign new tokens with?** `signing_pem/0` returns the
      private RSA key PEM. Attesto derives the public half and the `kid`
      from it (`Attesto.Key`), so the keystore never has to compute a
      thumbprint.

    * **What keys may verify a presented token?** `verification_pems/0`
      returns a list of PEMs (private or public) whose public halves are
      trusted. With a single key this is just `[signing_pem()]`. During a
      key rotation it carries both the outgoing and incoming keys so
      tokens minted under either verify, and `Attesto.Token.verify/3`
      selects the right one by the JWS header `kid`.

  Implementations decide *where* keys come from - an environment
  variable, a secrets manager, a file, a hardware module. Attesto only
  consumes the PEMs, so the security-sensitive resolution and any
  fail-fast boot checks stay in the host application.

  `Attesto.Keystore.Static` is a ready-made implementation for the common
  single-key (or manually-rotated) case.
  """

  @doc """
  The private RSA key PEM used to sign newly issued tokens.
  """
  @callback signing_pem() :: String.t()

  @doc """
  The PEMs (private or public) whose public halves are trusted to verify
  a presented token. MUST include the public half of whatever
  `signing_pem/0` currently returns.
  """
  @callback verification_pems() :: [String.t()]
end
