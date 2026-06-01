# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.1] - 2026-05-31

### Added

- `Attesto.Test.DPoPVerifier` - a server-side DPoP verification harness for
  host application suites, the counterpart to `Attesto.Test.DPoP`. From a plain
  request description (`method`, `url`, `headers`) it verifies the presented
  DPoP proof and, when `verify_token: true`, the access token, returning
  `{:ok, verified}` or an `{:error, challenge}` map carrying the HTTP status,
  the `WWW-Authenticate` challenge, and an optional `DPoP-Nonce`. It does not
  reimplement RFC 9449: it delegates every decision to the production verifiers
  `Attesto.DPoP.verify_proof/2` and `Attesto.Token.verify/3`, and mirrors the
  resource server's scheme handling (a DPoP-bound token presented as Bearer
  surfaces a `DPoP` challenge, RFC 9449 §7.1; a missing required nonce surfaces
  `use_dpop_nonce`, §8). It depends on neither Plug, Phoenix, nor any HTTP
  client, so it runs from any ExUnit suite.

- `Attesto.Test.DPoP` - DPoP test fixtures for host application suites
  (RFC 9449). Ships under `lib/` so a consumer can call it from its
  `test/` tree without depending on Attesto's own test support.
  `generate_key/1` mints a proof key (EC P-256 / `ES256` by default);
  `mint_access_token/4` mints a DPoP-sender-constrained access token bound
  to that key via `cnf.jkt` (RFC 7800); `proof/4` builds a valid proof JWT
  for a `(htm, htu)` pair, optionally carrying `ath` (RFC 9449 §4.3) and a
  server `nonce` (§8); `invalid_proof/5` builds a proof with a single
  deliberate defect (`:wrong_htm`, `:wrong_htu`, `:missing_ath`,
  `:expired`) for negative tests. Every fixture is built through the same
  primitives the production code uses (`Attesto.Token.mint/3`,
  `Attesto.DPoP.compute_jkt/1`, `Attesto.DPoP.compute_ath/1`,
  `Attesto.SigningAlg.infer/1`, `JOSE.JWS`), and embeds only the proof
  key's public half (RFC 9449 §4.2), so a fixture is correct by
  construction against `Attesto.DPoP.verify_proof/2` and stays in step
  with it.

## [0.6.0]

### Added

- `Attesto.IDToken.mint/3` rounds out the OpenID Connect Core §2 ID Token
  claim set: `auth_time` (REQUIRED when the request asked for it or carried
  `max_age`), `acr`, `amr`, and `azp` are accepted as optional inputs and
  omitted when absent. Arbitrary additional claims requested through the
  OIDC Core §5.5 `claims` parameter or a host userinfo mapping are supplied
  via `:extra_claims`, a string-keyed map merged after the protocol claims.
  The merge is non-overriding: a key colliding with a reserved protocol
  claim (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `azp`, `auth_time`,
  `acr`, `amr`, `at_hash`, `c_hash`) is rejected with
  `:reserved_claim_conflict`, and a non-map or non-string-keyed value with
  `:invalid_extra_claims`. `at_hash`/`c_hash` (OIDC Core §3.1.3.6,
  §3.3.2.11) were already present.
- `Attesto.AuthorizationRequest.validate/2` - `:require_nonce` option (default
  `false`). When `true`, a request with no `nonce` is rejected with a
  redirectable `invalid_request` error (OIDC Core §3.1.2.1); when `false`,
  `nonce` stays OPTIONAL and is carried through unenforced (RFC 6749 keeps the
  `code` flow at SHOULD). The OP policy is the host's, signalled per call.
- Authorization-code reuse detection (OAuth 2.0 Security BCP §4.13 /
  RFC 6749 §4.1.2). `Attesto.AuthorizationCode.issue/3` accepts an
  optional `:family_id` that links a code to the refresh-token family it
  spawns; it rides onto the redeemed `Attesto.AuthorizationCode.Grant`
  (new `:family_id` field). `Attesto.CodeStore` gains an OPTIONAL
  reuse-tracking pair: a `mark_consumed/2` callback and a third `take/1`
  return value `{:error, :consumed, meta}`. When a store implements them,
  `redeem/4` records the spent code's `family_id`/`subject` and surfaces a
  later replay of that code as `{:error, {:reuse, meta}}` so the caller can
  revoke the descendant family. The addition is purely additive and
  fail-safe: a store that does not implement the pair keeps the
  `{:ok, entry} | :error` `take/1` contract and a re-presented code stays
  `{:error, :invalid_grant}`, with single-use atomicity unchanged.
- Refresh-token rotation grace for honest retries. `Attesto.RefreshToken.rotate/3`
  now returns the same successor when the just-consumed parent is immediately
  retried by the same client, DPoP binding, and narrowed scope within
  `:rotation_grace_seconds` (default `10`). Outside that window, or on any
  mismatch, reuse still revokes the whole family. `Attesto.RefreshStore`
  entries now carry `:consumed_at` and `:successor`, and stores may implement
  `remember_successor/3` to support the idempotent retry path.
- `Attesto.Plug.Authenticate` accepts a `:credential_from_conn` fallback hook
  for host-owned credential channels such as first-party cookies. The
  `Authorization` header remains authoritative when present; the callback is
  consulted only when no usable header credential exists.
- `Attesto.Plug.OAuthError` supports transport hooks (`:send_error`,
  `:www_authenticate`, `:no_store`) so hosts can preserve their API error
  envelope while Attesto owns the OAuth status/challenge semantics.

### Changed

- `Attesto.AuthorizationRequest.validate/2` - `prompt` tokens are now validated
  against the fixed OIDC set `{none, login, consent, select_account}`; an unknown
  token is a redirectable `invalid_request` error (OIDC Core §3.1.2.1). The
  parsed list is still exposed for the controller, which enforces semantics such
  as `prompt=none` (the OP MUST NOT show UI).
- `c:Attesto.RefreshStore.consume/2` receives rotation options such as the
  claim timestamp and returns consumed records with enough metadata for
  retry/reuse decisions. This is the intentional 0.6 store-contract change.

### Security

- Closed a JWS signature-malleability gap in the compact-form boundary of
  both `Attesto.Token.verify/3` and `Attesto.IDToken.verify/3`. The boundary
  previously checked each segment against the base64url alphabet only
  (RFC 4648 §5), which accepts a non-canonical final character: the 342-byte
  RS256 signature segment is a partial quantum (342 rem 4 == 2) whose last
  character carries four unused low-order bits, so several distinct
  characters decode to the same signature bytes (RFC 4648 §3.5). JOSE's
  liberal decoder normalises such a variant and verifies it, so a tampered
  serialization that is not byte-identical to the issuer's token was
  accepted. The boundary now requires each segment to round-trip through
  `Base.url_decode64/2` and `Base.url_encode64/2` byte-identically, rejecting
  padding, non-alphabet bytes, and non-zero unused trailing bits in one
  check, before the token reaches JOSE. Canonical unpadded base64url tokens
  are unaffected; the empty signature segment of an `alg:none` token still
  round-trips and is classified `:invalid_signature`.

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
