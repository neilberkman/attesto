# RFC Checklist

Audit date: 2026-05-30

This checklist maps Attesto's protocol claims to the RFC points the library
appears to own, then records whether implementation and tests cover them.

Status legend:

- Covered: code and tests cover the point.
- Partial: code covers only part of the point, or tests intentionally pin a
  known gap/current behavior.
- Missing: no implementation or direct test coverage was found.
- Host: owned by the embedding authorization/resource server, not this package.
- N/A: not applicable to this package's scope.

Primary RFC sources used:

- RFC 6749 - OAuth 2.0 Authorization Framework: https://www.rfc-editor.org/rfc/rfc6749.html
- RFC 6750 - Bearer Token Usage: https://www.rfc-editor.org/rfc/rfc6750.html
- RFC 7009 - Token Revocation: https://www.rfc-editor.org/rfc/rfc7009.html
- RFC 7515 - JSON Web Signature: https://www.rfc-editor.org/rfc/rfc7515.html
- RFC 7517 - JSON Web Key: https://www.rfc-editor.org/rfc/rfc7517.html
- RFC 7519 - JSON Web Token: https://www.rfc-editor.org/rfc/rfc7519.html
- RFC 7636 - PKCE: https://www.rfc-editor.org/rfc/rfc7636.html
- RFC 7638 - JWK Thumbprint: https://www.rfc-editor.org/rfc/rfc7638.html
- RFC 7800 - Proof-of-Possession Key Semantics for JWTs: https://www.rfc-editor.org/rfc/rfc7800.html
- RFC 8414 - OAuth 2.0 Authorization Server Metadata: https://www.rfc-editor.org/rfc/rfc8414.html
- RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens: https://www.rfc-editor.org/rfc/rfc8705.html
- RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens: https://www.rfc-editor.org/rfc/rfc9068.html
- RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession: https://www.rfc-editor.org/rfc/rfc9449.html
- RFC 9700 - Best Current Practice for OAuth 2.0 Security: https://www.rfc-editor.org/rfc/rfc9700.html

## High-Priority Gaps

Status as of the 2026-05-30 follow-up pass (several items closed since the
original audit; see "Resolved" markers).

| ID | Gap | Status | Evidence |
| --- | --- | --- | --- |
| GAP-01 | DPoP embedded JWK metadata. A proof JWK declaring `use: "enc"` or `key_ops` without `verify` is **rejected**, and a JWK `alg` contradicting the header `alg` is now **rejected** outright (`alg_consistent?/2`, `:invalid_jwk`) rather than left to the signature math. | Resolved | `lib/attesto/dpop.ex` `usable_for_signing?/1`, `alg_consistent?/2`; `test/attesto/dpop_header_test.exs`. |
| GAP-02 | DPoP `htu`. **Resolved**: a proof whose own `htu` carries a query or fragment is now rejected (RFC 9449 §4.3 requires the client to construct it without them); the server-observed URI is still normalised. Every other dimension was already stricter than a normalizing verifier. | Resolved | `lib/attesto/dpop.ex` `check_htu/2`; `test/attesto/dpop_htu_test.exs`, `test/attesto/dpop_test.exs`. |
| GAP-03 | DPoP server-issued nonce (RFC 9449 §8). **Resolved**: a `:nonce_check` callback on `verify_proof/2` (the `:use_dpop_nonce` error), the `Attesto.DPoP.NonceStore` behaviour + cluster-guarded ETS impl, and `Attesto.Plug.Authenticate` answering the `DPoP-Nonce` challenge. | Resolved | `lib/attesto/dpop.ex` `check_nonce/2`, `lib/attesto/dpop/nonce_store*.ex`, `lib/attesto/plug/authenticate.ex`. |
| GAP-04 | RFC 8705 / PAR metadata extensions in `Discovery.metadata/2`. **Resolved**: `tls_client_certificate_bound_access_tokens`, `mtls_endpoint_aliases`, the revocation/introspection auth-method fields, and the PAR fields are now pass-through host fields. | Resolved | `lib/attesto/discovery.ex` `@host_fields`; `test/attesto/metadata_hardening_test.exs`. |
| GAP-05 | RFC 8414 §2 issuer URL shape. **Resolved**: `Config.new/1` now requires the issuer to be an https URL with a host and no query/fragment. | Resolved | `lib/attesto/config.ex` `validate_issuer_url!/1`; `test/attesto/metadata_hardening_test.exs`. |
| GAP-06 | RFC 9068 `typ: "at+jwt"` JOSE header. **Resolved**: access tokens carry the `at+jwt` header by default, configurable via `Config`'s `access_token_header_typ` (a host can set a custom value or `nil`). The payload `typ` still distinguishes access/refresh. | Resolved | `lib/attesto/token.ex` `jose_header/3`, `lib/attesto/config.ex`; `test/attesto/token_at_jwt_test.exs`. |
| GAP-07 | RFC 7009 token revocation. **Resolved**: `Attesto.Revocation.revoke/3` revokes a refresh token's whole family over the `RefreshStore`, with the no-existence-oracle and fail-closed client binding. | Resolved | `lib/attesto/revocation.ex`; `test/attesto/revocation_test.exs`. |
| GAP-08 | Key parsing now fails loudly with clear `ArgumentError`s on non-RSA / multi-key / empty / garbage PEMs (no more `FunctionClauseError` or silent `[]`); the stale test header is fixed. Encrypted/password-protected PEM behaviour is now pinned by a test; the only residual is cosmetic (the encrypted case raises the opaque internal error rather than a clear `ArgumentError`). | Resolved | `lib/attesto/key.ex` `jwk/1`, `decode_rsa_private_key!/1`, `rsa_public_from_private/1`; `test/attesto/key_format_test.exs`, `test/attesto/key_encrypted_test.exs`. |

## OAuth 2.0 Core and Security BCP

| ID | RFC Point | Status | Code | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| OAUTH-01 | RFC 6749 scope-token ABNF is `1*NQCHAR`: printable ASCII excluding space, double quote, and backslash. | Covered | `lib/attesto/scope.ex:89` | `test/attesto/scope_token_test.exs:43` | Tests walk the printable range and reject controls, whitespace, non-ASCII, quote, and backslash. |
| OAUTH-02 | Scope values in issued credentials must be unambiguous when space-delimited. | Covered | `lib/attesto/token.ex:358`, `lib/attesto/authorization_code.ex:263`, `lib/attesto/refresh_token.ex:300` | `test/attesto/scope_token_test.exs:133`, `test/attesto/scope_token_test.exs:180`, `test/attesto/scope_token_test.exs:220` | All issuance surfaces use `Scope.valid_token?/1`. |
| OAUTH-03 | Access-token `scope` is a string; resource policy is outside OAuth core. | Covered | `lib/attesto/token.ex:623` | `test/attesto/scope_token_test.exs:248`, `test/attesto/token_verify_test.exs:265` | Verify checks shape, not policy. |
| OAUTH-04 | Authorization codes are single use. | Covered | `lib/attesto/authorization_code.ex:137`, `lib/attesto/code_store.ex:11`, `lib/attesto/code_store/ets.ex:55` | `test/attesto/authorization_code_test.exs:208`, `test/attesto/grants_concurrency_test.exs:32` | Code is consumed with `take/1` before validation. |
| OAUTH-05 | Authorization-code redemption binds the code to the client it was issued to. | Covered | `lib/attesto/authorization_code.ex:157` | `test/attesto/grants_client_scope_test.exs:39` | Default is fail-closed; opt-out is explicit for PKCE-only hosts. |
| OAUTH-06 | Redirect URI comparison is exact, not normalized. | Covered | `lib/attesto/authorization_code.ex:221` | `test/attesto/authorization_code_test.exs:245` | Covers trailing-slash and missing parameter mismatch. |
| OAUTH-07 | Authorization-code expiry is enforced. | Covered | `lib/attesto/authorization_code.ex:217` | `test/attesto/authorization_code_test.exs:289` | Boundary at `expires_at == now` is expired. |
| OAUTH-08 | Authorization-code grants require PKCE in modern deployments. | Covered | `lib/attesto/authorization_code.ex:14`, `lib/attesto/authorization_code.ex:189` | `test/attesto/authorization_code_test.exs:113`, `test/attesto/grants_smoke_test.exs` | No PKCE-less issue path exists. |
| OAUTH-09 | Refresh tokens are bound to the client for which they were issued. | Covered | `lib/attesto/refresh_token.ex:200` | `test/attesto/grants_client_scope_test.exs:64` | Default is fail-closed when `client_id` is present. |
| OAUTH-10 | Refresh-token scope requests can narrow but not widen the original grant. | Covered | `lib/attesto/refresh_token.ex:218` | `test/attesto/grants_client_scope_test.exs:82` | Narrowed successor cannot later re-widen. |
| OAUTH-11 | Refresh-token rotation detects replay and revokes the token family. | Covered | `lib/attesto/refresh_token.ex:107`, `lib/attesto/refresh_store.ex:11`, `lib/attesto/refresh_store/ets.ex:101` | `test/attesto/refresh_token_test.exs:128`, `test/attesto/grants_concurrency_test.exs:55`, `test/attesto/concurrency_swarm_test.exs:35` | Aligns with RFC 9700 replay detection guidance. |
| OAUTH-12 | Refresh-token recoverable errors should not burn a still-valid token. | Covered | `lib/attesto/refresh_token.ex:137` | `test/attesto/refresh_token_test.exs:193`, `test/attesto/grants_client_scope_test.exs:72` | DPoP/client/scope failures are checked before consume. |
| OAUTH-13 | Refresh tokens should expire after inactivity or policy interval. | Covered | `lib/attesto/refresh_token.ex:29`, `lib/attesto/refresh_token.ex:277` | `test/attesto/refresh_token_test.exs:62`, `test/attesto/refresh_token_test.exs:104` | Rotation issues a successor with a fresh TTL. |
| OAUTH-14 | Token endpoint client authentication and HTTP error response bodies. | Host | N/A | N/A | Attesto is protocol logic; the host controller owns OAuth HTTP parameters and client auth schemes. |
| OAUTH-15 | Bearer-token `WWW-Authenticate` challenges and RFC 6750 resource errors. | Host | N/A | N/A | Resource-server Plug/controller layer owns this. |
| OAUTH-16 | Authorization endpoint `state`, CSRF, clickjacking, consent UI, redirect registration, and mix-up defenses. | Host | N/A | N/A | No authorization UI/endpoint implementation in this package. |
| OAUTH-17 | RFC 7009 token revocation. | Covered | `lib/attesto/revocation.ex` | `test/attesto/revocation_test.exs` | `Revocation.revoke/3` revokes a refresh token's family; no-existence oracle + fail-closed client binding. The HTTP endpoint is host-owned. |

## PKCE

| ID | RFC Point | Status | Code | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| PKCE-01 | `code_verifier` is 43-128 characters from the unreserved alphabet. | Covered | `lib/attesto/pkce.ex:42` | `test/attesto/pkce_test.exs:81`, `test/attesto/property_test.exs:331` | Boundary and invalid character tests exist. |
| PKCE-02 | S256 challenge is base64url(SHA-256(verifier)) without padding. | Covered | `lib/attesto/pkce.ex:51` | `test/attesto/pkce_test.exs:13`, `test/attesto/conformance_vectors_test.exs:72` | Pinned to RFC 7636 Appendix B. |
| PKCE-03 | `plain` and unknown methods are rejected. | Covered | `lib/attesto/pkce.ex:90`, `lib/attesto/authorization_code.ex:175` | `test/attesto/pkce_test.exs:56`, `test/attesto/authorization_code_test.exs:128` | Closes downgrade path. |
| PKCE-04 | Wrong, missing, empty, or malformed verifier fails redemption. | Covered | `lib/attesto/authorization_code.ex:231` | `test/attesto/authorization_code_test.exs:260` | All PKCE failures collapse to `:pkce_failed`. |
| PKCE-05 | Metadata advertises S256 support. | Covered | `lib/attesto/discovery.ex:76` | `test/attesto/discovery_test.exs:33` | Matches RFC 9700 recommendation to publish PKCE support. |
| PKCE-06 | Token request with verifier is accepted only if a challenge was stored. | Covered | `lib/attesto/authorization_code.ex:86`, `lib/attesto/authorization_code.ex:189` | `test/attesto/authorization_code_test.exs:113` | Stored code always has a valid S256 challenge. |

## JWT, JWS, JWK, Thumbprints, and `cnf`

| ID | RFC Point | Status | Code | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| JWT-01 | Tokens are compact JWS/JWTs with RS256 signature verification. | Covered | `lib/attesto/token.ex:415`, `lib/attesto/token.ex:474` | `test/attesto/token_mint_test.exs:89`, `test/attesto/token_verify_test.exs:126`, `test/attesto/conformance_vectors_test.exs:172` | Uses published RFC 7515 RS256 vector. |
| JWT-02 | Algorithm confusion is rejected (`none`, HS*). | Covered | `lib/attesto/token.ex:61`, `lib/attesto/token.ex:474` | `test/attesto/security_negative_test.exs:151`, `test/attesto/token_verify_test.exs:149` | `verify_strict` allow-list is `["RS256"]`. |
| JWT-03 | `kid` selection supports rotation and rejects unknown/wrong key IDs. | Covered | `lib/attesto/token.ex:448` | `test/attesto/security_negative_test.exs:89`, `test/attesto/token_verify_test.exs:561` | Kid-less trusted-key fallback is documented and tested. |
| JWT-04 | Unsupported JWS `crit` protected headers are invalid. | Covered | `lib/attesto/token.ex:437`, `lib/attesto/dpop.ex:291` | `test/attesto/security_negative_test.exs:201`, `test/attesto/dpop_header_test.exs:100` | Rejects on presence, including empty/non-list DPoP `crit`. |
| JWT-05 | Malformed compact input does not crash or leak parser detail. | Covered | `lib/attesto/token.ex:493`, `lib/attesto/dpop.ex:238` | `test/attesto/token_verify_test.exs:171`, `test/attesto/dpop_test.exs:558`, `test/attesto/security_negative_test.exs:231` | Deeply nested JSON is also covered. |
| JWT-06 | Required claims have the expected shape: `iss`, `aud`, `exp`, `iat`, `jti`, `sub`, `scope`, principal kind, and token purpose. | Covered | `lib/attesto/token.ex:572`, `lib/attesto/token.ex:619` | `test/attesto/token_verify_test.exs:187`, `test/attesto/token_verify_test.exs:242` | Per-kind required claims are checked too. |
| JWT-07 | `aud` can be a string or an array of strings containing the expected audience. | Covered | `lib/attesto/token.ex:578` | `test/attesto/token_temporal_test.exs:142`, `test/attesto/token_verify_test.exs:199` | Mixed/nested arrays are rejected. |
| JWT-08 | `exp` is enforced, and `nbf`/future `iat` are not accepted beyond skew. | Covered | `lib/attesto/token.ex:594`, `lib/attesto/token.ex:600`, `lib/attesto/token.ex:610` | `test/attesto/token_temporal_test.exs:81`, `test/attesto/token_temporal_test.exs:110`, `test/attesto/token_verify_test.exs:223` | `exp == now` is expired. |
| JWT-09 | Reserved protocol claims cannot be shadowed by caller-provided custom claims. | Covered | `lib/attesto/token.ex:337`, `lib/attesto/config.ex:65` | `test/attesto/token_mint_test.exs:187`, `test/attesto/config_test.exs:179` | Includes configurable principal-kind claim. |
| JWT-10 | JWK thumbprints use RFC 7638 canonicalization. | Covered | `lib/attesto/key.ex:36`, `lib/attesto/dpop.ex:196` | `test/attesto/conformance_vectors_test.exs:46`, `test/attesto/thumbprint_test.exs:44`, `test/parity/cross_language_parity_test.exs:205` | Pinned to RFC 7638 and Python `joserfc`. |
| JWT-11 | SHA-256 base64url thumbprint shape rejects non-canonical trailing bits. | Covered | `lib/attesto/thumbprint.ex:20` | `test/attesto/thumbprint_test.exs:68`, `test/attesto/mtls_test.exs:167` | Shared by PKCE, DPoP `jkt`, and mTLS `x5t#S256`. |
| JWT-12 | JWKS publishes public material only with `kid`, `use: "sig"`, and `alg: "RS256"`. | Covered | `lib/attesto/jwks.ex:51`, `lib/attesto/key.ex` `ensure_rsa!/1` | `test/attesto/jwks_test.exs`, `test/attesto/key_format_test.exs` | Private RSA members are checked absent. A non-RSA key cannot enter the set mislabelled `alg: "RS256"`: `Key.jwk/1` rejects any non-RSA PEM (attesto is RS256-only), so an EC key fails loudly rather than being published under an RS256 alg. |
| JWT-13 | Key format support is predictable for real operator PEMs. | Partial | `lib/attesto/key.ex:60`, `lib/attesto/key.ex:85`, `lib/attesto/key.ex:109` | `test/attesto/key_format_test.exs:54`, `test/attesto/key_format_test.exs:95`, `test/attesto/key_format_test.exs:116`, `test/attesto/key_format_test.exs:142`, `test/attesto/key_format_test.exs:163`, `test/attesto/key_format_test.exs:195`, `test/attesto/key_format_test.exs:225` | PKCS#1, PKCS#8, CRLF, public-only verification PEMs, EC/private-key mismatch, empty/garbage, and multi-key PEMs are covered. Encrypted/password-protected PEM behaviour is now pinned by `test/attesto/key_encrypted_test.exs`; the residual is cosmetic - an encrypted PEM raises the opaque internal error rather than the clear `ArgumentError` the other malformed-key paths raise. |
| JWT-14 | RFC 7800 `cnf` represents one proof-of-possession key. | Covered | `lib/attesto/token.ex:376`, `lib/attesto/token.ex:510` | `test/attesto/token_mint_test.exs:272`, `test/attesto/token_verify_test.exs:504` | Only exactly one of `jkt` or `x5t#S256` is accepted. |
| JWT-15 | DPoP and mTLS confirmation schemes are mutually exclusive. | Covered | `lib/attesto/token.ex:381`, `lib/attesto/token.ex:528` | `test/attesto/token_mint_test.exs:362`, `test/attesto/security_negative_test.exs:282` | Cross-presentation is rejected even when the matching proof is also present. |
| JWT-16 | RFC 9068 JWT access-token profile header `typ: "at+jwt"`. | Covered | `lib/attesto/token.ex` `jose_header/3`, `sign/2` | `test/attesto/token_at_jwt_test.exs` | Access tokens carry `typ: "at+jwt"` by default (configurable via `Config.access_token_header_typ`, or `nil` for none); refresh tokens carry no `typ`. Signed via `JOSE.JWS.sign/3` so the header is emitted verbatim (`JOSE.JWT.sign/3` would inject `typ: "JWT"`). The full RFC 9068 *claim* profile (resource/audience policy) remains partly host-owned per JWT-17. |
| JWT-17 | RFC 9068 authorization claims and resource/audience relationship. | Partial | `lib/attesto/token.ex:187`, `lib/attesto/config.ex:55` | `test/attesto/token_mint_test.exs:56`, `test/attesto/token_temporal_test.exs:142` | `aud` is a configured default. Resource indicators and scope-to-resource policy are host-owned. |
| JWT-18 | JWT access-token privacy and client opacity guidance. | Host | N/A | N/A | Attesto emits signed but unencrypted JWTs. Host policy decides whether token contents are appropriate for clients/end users. |

## DPoP

| ID | RFC Point | Status | Code | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| DPOP-01 | DPoP proof is a JWS/JWT whose JOSE `typ` is `dpop+jwt`. | Covered | `lib/attesto/dpop.ex:282` | `test/attesto/dpop_test.exs:157` | Missing/wrong `typ` rejected. |
| DPOP-02 | DPoP proof `alg` must be asymmetric; `none` and HS* rejected. | Covered | `lib/attesto/dpop.ex:70`, `lib/attesto/dpop.ex:285` | `test/attesto/dpop_test.exs:179`, `test/attesto/dpop_header_test.exs:264` | Whitelist includes ES, RS, PS, and EdDSA. |
| DPOP-03 | Proof header must carry a public JWK. | Covered | `lib/attesto/dpop.ex:299` | `test/attesto/dpop_test.exs:241` | Missing/empty/unparseable JWKs fail closed. |
| DPOP-04 | Proof header JWK must not contain private key material. | Covered | `lib/attesto/dpop.ex:299`, `lib/attesto/dpop.ex:319` | `test/attesto/dpop_test.exs:266`, `test/attesto/dpop_test.exs:276` | Rejects EC/RSA private members and symmetric `k`. |
| DPOP-05 | Optional JWK metadata should not contradict use as a signing key. | Covered | `lib/attesto/dpop.ex` `usable_for_signing?/1`, `alg_consistent?/2` | `test/attesto/dpop_header_test.exs` | `use != "sig"` and `key_ops` without `verify` are rejected as `:invalid_jwk`. A JWK `alg` that contradicts the header `alg` is also rejected as `:invalid_jwk` before any signature math. |
| DPOP-06 | Proof signature must verify under the embedded JWK. | Covered | `lib/attesto/dpop.ex:328` | `test/attesto/dpop_test.exs:316` | Wrong signer and tampered payload are rejected. |
| DPOP-07 | `htm` must match the request method, case-sensitively. | Covered | `lib/attesto/dpop.ex:345` | `test/attesto/dpop_test.exs:346` | Lowercase `post` is rejected. |
| DPOP-08 | `htu` must bind to the request URI without query/fragment. | Covered | `lib/attesto/dpop.ex` `check_htu/2`, `normalize_htu/1` | `test/attesto/dpop_htu_test.exs`, `test/attesto/dpop_test.exs` | The server-observed request URI is normalized (query/fragment stripped) before comparison, and a proof whose own `htu` carries a query or fragment is now rejected (`:invalid_htu`) - the proof cannot widen its binding by appending a query the server would strip. |
| DPOP-09 | `htu` comparison should be robust around URI normalization edge cases. | Partial | `lib/attesto/dpop.ex:352` | `test/attesto/dpop_htu_test.exs:117`, `test/attesto/dpop_htu_test.exs:147`, `test/attesto/dpop_htu_test.exs:177`, `test/attesto/dpop_htu_test.exs:221`, `test/attesto/dpop_htu_test.exs:250` | Raw-string compare is stricter than RFC 3986 normalization for host case/default ports/percent triplets, but accepts identical userinfo and has a case-sensitive `https://` gate. |
| DPOP-10 | `iat` freshness and future skew are enforced. | Covered | `lib/attesto/dpop.ex:380` | `test/attesto/dpop_test.exs:425` | Default age window is 60 seconds plus 5 seconds future skew. |
| DPOP-11 | `jti` is required and replay identifiers are bounded. | Covered | `lib/attesto/dpop.ex:394` | `test/attesto/dpop_test.exs:477` | Adds a 256-byte cap for cache safety. |
| DPOP-12 | Replay protection rejects previously seen proof `jti` values. | Covered | `lib/attesto/dpop.ex:405`, `lib/attesto/dpop/replay_cache.ex:92`, `lib/attesto/plug/authenticate.ex` `verify_dpop_proof/4` | `test/attesto/dpop_test.exs:678`, `test/attesto/dpop_test.exs:752`, `test/attesto/concurrency_swarm_test.exs:133`, `test/attesto/plug/authenticate_test.exs` | The pure verifier treats an absent `:replay_check` as no protection (it is a host-injected seam), but `Attesto.Plug.Authenticate` **fails closed**: a DPoP request is refused (401, `replay_check_unconfigured`) unless `:replay_check` is wired or `dpop_replay_unprotected_acknowledged?: true` is set, so an unprotected DPoP endpoint cannot silently ship. ETS cache is single-node with a boot guard for clustered BEAMs. |
| DPOP-13 | `ath` binds a proof to the access token on protected-resource requests. | Covered | `lib/attesto/dpop.ex:441` | `test/attesto/dpop_test.exs:515`, `test/attesto/conformance_vectors_test.exs:103` | Pinned to RFC 9449 `ath` vector. |
| DPOP-14 | Token endpoint proofs can omit `ath`; present `ath` is returned but not enforced when no access token exists yet. | Covered | `lib/attesto/dpop.ex:441` | `test/attesto/dpop_test.exs:541` | Matches token endpoint usage. |
| DPOP-15 | DPoP-bound access-token response uses token type `DPoP` and embeds `cnf.jkt`. | Covered | `lib/attesto/token.ex:403` | `test/attesto/token_mint_test.exs:272`, `test/attesto/smoke_test.exs:103` | mTLS-bound tokens remain `Bearer`. |
| DPOP-16 | Access-token verification enforces `cnf.jkt` against the verified proof key. | Covered | `lib/attesto/token.ex:536` | `test/attesto/token_verify_test.exs:389` | Missing/mismatched proof is rejected. |
| DPOP-17 | Authorization code can be bound to the DPoP key used at the token endpoint. | Covered | `lib/attesto/authorization_code.ex:29`, `lib/attesto/authorization_code.ex:242` | `test/attesto/authorization_code_test.exs:307` | Unbound code forbids a presented DPoP binding. |
| DPOP-18 | Refresh token can be sender-constrained with DPoP. | Covered | `lib/attesto/refresh_token.ex:16`, `lib/attesto/refresh_token.ex:281` | `test/attesto/refresh_token_test.exs:157` | Binding matrix mirrors access tokens. |
| DPOP-19 | DPoP nonce challenge/response flows. | Covered | `lib/attesto/dpop.ex` `check_nonce/2`, `lib/attesto/dpop/nonce_store.ex`, `lib/attesto/dpop/nonce_store/ets.ex`, `lib/attesto/plug/authenticate.ex` | `test/attesto/dpop_nonce_test.exs`, `test/attesto/plug/authenticate_test.exs` | `verify_proof/2` takes a `:nonce_check` callback returning `:use_dpop_nonce`; the `Attesto.DPoP.NonceStore` behaviour + cluster-guarded ETS impl issue/validate nonces; `Attesto.Plug.Authenticate` answers with a `DPoP-Nonce` header and requires `:nonce_issue` whenever `:nonce_check` is wired. |
| DPOP-20 | DPoP HTTP header parsing, case-insensitive header name, and error response headers. | Host | N/A | N/A | This package accepts the proof JWT string; HTTP extraction and challenges belong to the host. |

## mTLS and Certificate-Bound Tokens

| ID | RFC Point | Status | Code | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| MTLS-01 | `x5t#S256` is base64url(SHA-256(DER cert)) without padding. | Covered | `lib/attesto/mtls.ex:49` | `test/attesto/mtls_test.exs:28`, `test/attesto/token_mint_test.exs:380` | Computes only after X.509 parse succeeds. |
| MTLS-02 | Non-certificate input is rejected rather than thumbprinted. | Covered | `lib/attesto/mtls.ex:61`, `lib/attesto/mtls.ex:96` | `test/attesto/mtls_test.exs:80` | Covers empty, non-binary, random, non-cert ASN.1, and truncated DER. |
| MTLS-03 | mTLS-bound tokens carry and enforce `cnf.x5t#S256`. | Covered | `lib/attesto/token.ex:394`, `lib/attesto/token.ex:549` | `test/attesto/token_mint_test.exs:317`, `test/attesto/token_verify_test.exs:446` | Missing/mismatched cert thumbprint rejected. |
| MTLS-04 | mTLS-bound access tokens use OAuth token type `Bearer`. | Covered | `lib/attesto/token.ex:403` | `test/attesto/token_mint_test.exs:317` | RFC 8705 binding does not change token type. |
| MTLS-05 | DPoP and mTLS bindings cannot be mixed. | Covered | `lib/attesto/token.ex:381`, `lib/attesto/token.ex:528` | `test/attesto/token_mint_test.exs:362`, `test/attesto/security_negative_test.exs:282` | Cross-scheme proof options are rejected. |
| MTLS-06 | TLS client authentication, chain validation, SAN/DN matching, and certificate revocation checking. | Host | `lib/attesto/mtls.ex:35` | N/A | The TLS terminator/host app owns this; Attesto only computes/verifies thumbprints. |
| MTLS-07 | RFC 8705 metadata values for `tls_client_auth` and `self_signed_tls_client_auth`. | Host | N/A | N/A | Client registration and token endpoint auth method support are host-owned. |
| MTLS-08 | RFC 8705 authorization-server metadata extensions. | Covered | `lib/attesto/discovery.ex` `@host_fields` | `test/attesto/metadata_hardening_test.exs` | `tls_client_certificate_bound_access_tokens` and `mtls_endpoint_aliases` are pass-through host fields. |

## Authorization Server Metadata and JWKS

| ID | RFC Point | Status | Code | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| DISC-01 | Metadata includes issuer, token endpoint, and JWKS URI. | Covered | `lib/attesto/discovery.ex:70` | `test/attesto/discovery_test.exs:24` | JWKS URI default is derived from issuer and overridable. |
| DISC-02 | Metadata issuer uses HTTPS and has no query/fragment. | Covered | `lib/attesto/config.ex` `validate_issuer_url!/1` | `test/attesto/metadata_hardening_test.exs` | `Config.new/1` rejects a non-https issuer, a hostless issuer, and any query/fragment. |
| DISC-03 | Authorization endpoint is present when grant types need it. | Partial | `lib/attesto/discovery.ex:37`, `lib/attesto/discovery.ex:70` | `test/attesto/discovery_test.exs:50` | Host supplies `authorization_endpoint`; `grant_types_supported` can be overridden without requiring it. |
| DISC-04 | Supported PKCE methods are advertised. | Covered | `lib/attesto/discovery.ex:76` | `test/attesto/discovery_test.exs:33` | S256 only. |
| DISC-05 | Supported DPoP signing algorithms are advertised. | Covered | `lib/attesto/discovery.ex:77` | `test/attesto/discovery_test.exs:33` | Uses `DPoP.allowed_algs/0`. |
| DISC-06 | Host-specific metadata is pass-through and nil values are dropped. | Partial | `lib/attesto/discovery.ex:37`, `lib/attesto/discovery.ex:80` | `test/attesto/discovery_test.exs:50` | Covers a useful subset, but not all RFC 8414/extension fields. |
| DISC-07 | JWKS output is a public JWK Set suitable for a JWKS endpoint. | Covered | `lib/attesto/jwks.ex:41` | `test/attesto/jwks_test.exs:11` | Endpoint routing/JSON serialization is host-owned. |
| DISC-08 | JWKS supports rotation windows and de-duplicates keys. | Covered | `lib/attesto/jwks.ex:43` | `test/attesto/jwks_test.exs:29`, `test/attesto/jwks_test.exs:38` | Publishes every verification key once by `kid`. |
| DISC-09 | RFC 7009 revocation endpoint metadata should match an actual endpoint. | Partial | `lib/attesto/discovery.ex:37` | `test/attesto/discovery_test.exs:69` | The `revocation_endpoint` field is advertised if the host passes it. Attesto provides the revocation *logic* (`Attesto.Revocation.revoke/3`, see OAUTH-17), but the host owns the HTTP endpoint the metadata names. |

## Stores, Concurrency, and Deployment Boundaries

| ID | RFC Point | Status | Code | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| STORE-01 | Authorization code store `take/1` must be atomic. | Covered | `lib/attesto/code_store.ex:11`, `lib/attesto/code_store/ets.ex:55` | `test/support/code_store_contract.ex:62`, `test/attesto/grants_concurrency_test.exs:32` | ETS uses `:ets.take/2`; production stores must satisfy the behavior contract. |
| STORE-02 | Refresh store `consume/1` must be atomic compare-and-set. | Covered | `lib/attesto/refresh_store.ex:11`, `lib/attesto/refresh_store/ets.ex:101` | `test/support/refresh_store_contract.ex:73`, `test/attesto/grants_concurrency_test.exs:55` | ETS serializes mutation through GenServer. |
| STORE-03 | Refresh family revocation must be sticky under races. | Covered | `lib/attesto/refresh_store.ex:60`, `lib/attesto/refresh_store/ets.ex:89`, `lib/attesto/refresh_store/ets.ex:119` | `test/support/refresh_store_contract.ex:150`, `test/attesto/concurrency_swarm_test.exs:92` | Late successor inserts into revoked families are refused. |
| STORE-04 | DPoP replay cache must reject duplicate `jti` values across the acceptance window. | Covered | `lib/attesto/dpop/replay_cache.ex:92`, `lib/attesto/dpop.ex:431` | `test/attesto/dpop_test.exs:775`, `test/attesto/concurrency_swarm_test.exs:133` | TTL is derived from verifier max age plus future skew when wired via `verify_proof/2`. |
| STORE-05 | Per-node ETS stores/caches are not sufficient for multi-node deployments unless routing is sticky or stores are shared. | Covered | `lib/attesto/cluster_guard.ex`; all ETS stores call `assert_single_node!/2` in `init` | `test/attesto/cluster_guard_test.exs` | Every ETS store (code, refresh, replay, nonce) now refuses to boot on a clustered BEAM unless `multi_node_acknowledged?: true`, forcing a shared-store choice. The engine itself is pure/stateless and cluster-safe by construction. |
