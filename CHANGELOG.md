# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1]

### Added

- `Attesto.IDToken` - mint and verify OpenID Connect ID Tokens (OIDC Core
  1.0 §2), including `at_hash`/`c_hash` generation, `nonce`, and the
  client-id audience and generic `JWT` `typ` that distinguish an ID Token
  from an RFC 9068 access token. Shares the keystore/`kid`/RS256 path with
  `Attesto.Token`.
- `Attesto.AuthorizationRequest` - protocol-shape validation for the
  authorization endpoint (RFC 6749 §4.1.1, OIDC Core §3.1.2.1, PKCE
  §4.3): `response_type`, `client_id`, exact-match `redirect_uri`,
  scope/`openid` detection, and the PKCE parameters.
- `Attesto.OpenIDDiscovery` - the OpenID Provider Metadata document
  (OIDC Discovery 1.0 §3) served from `/.well-known/openid-configuration`,
  built on top of `Attesto.Discovery`.
- `mix check` alias running formatting, `--warnings-as-errors` compile,
  property tests, and Credo strict in one command.

### Security

- DPoP replay cache: closed a race in the expired-entry re-admission path.
  `Attesto.DPoP.ReplayCache.check_and_record/2` performed a non-atomic
  lookup-then-insert, so at the exact TTL boundary two concurrent callers
  could both re-admit a just-expired `jti` and a proof could be replayed
  more than once. Re-admission is now a single atomic compare-and-delete
  (`:ets.select_delete/2` guarded on expiry) followed by `insert_new/2`, so
  exactly one caller wins and the losers see `:replay`.
- Token verification now enforces canonical compact-JWS form at its own
  boundary. `Attesto.Token.verify/3` and `Attesto.IDToken.verify/3` reject
  any `=` padding or non-base64url byte in a compact segment before the
  token reaches JOSE, refusing to verify a serialization the issuer never
  emitted (JOSE's decoder would otherwise tolerantly normalize trailing
  padding). Unpadded base64url tokens are unaffected.

### Fixed

- Documentation: the authorization-code single-use note now links the
  `Attesto.CodeStore` `take/1` callback with the correct callback
  reference, clearing a docs-build warning.
