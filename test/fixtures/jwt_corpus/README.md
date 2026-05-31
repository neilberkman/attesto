# Negative JWT corpus

A fixed, on-disk corpus of malformed and adversarial JWTs, each paired with
the `Attesto.Token.verify/3` error atom it MUST produce. It is consumed by
`test/attesto/token_negative_corpus_test.exs`, which installs `signing_key.pem`
as the `Attesto.Keystore.Static` keystore, reads every `<name>.jwt`, and
asserts the documented `expected_error`.

Unlike the assertions that round-trip through `Attesto.Token.mint/3`, these
fixtures are *frozen bytes*. They pin behaviour that a mint helper can never
exercise — base64url corruption, non-UTF-8 payloads, control characters in the
JSON, padding remnants, segment-count anomalies — and they hold the wire form
stable across refactors so a parser regression surfaces as a corpus diff rather
than a silently changed code path.

## Layout

  * `signing_key.pem` — the fixed RSA private key the corpus is signed with.
    The companion test installs it as the Static keystore so the
    real-signature fixtures verify against a known key (and the deliberately
    wrong-`kid` fixture fails selection against it).
  * `<name>.jwt` — one token string per attack vector. A single line, **no
    trailing newline**; some fixtures are hand-assembled from raw segments and
    a trailing newline would change the bytes under test.
  * `<name>.json` — companion metadata:
      * `name` — matches the file stem.
      * `attack_vector` — what is malformed and why it is dangerous.
      * `expected_error` — the `verify/3` outcome as a string: an error atom
        (e.g. `"invalid_token"`, `"expired"`, `"unsupported_confirmation"`) or
        `"ok"` for the resource-exhaustion fixture that must verify cleanly
        rather than crash.
      * `notes` — the RFC clause or invariant the case anchors.

## Frozen clock

The temporal fixtures were minted against a frozen `now = 1700000000`
(2023-11-14T22:13:20Z). The companion test MUST verify them with
`now: 1_700_000_000`, otherwise `exp`/`nbf`/`iat` edges drift. (The corpus is
otherwise time-independent.)

## Coverage

| Group | Files | Expected error |
| --- | --- | --- |
| base64url / segment corruption | 01–05 | `invalid_token` |
| malformed JSON / non-UTF-8 header & payload | 06–10 | `invalid_token` |
| temporal edges (exp==now, future nbf/iat, non-int nbf) | 11–14 | `expired` / `not_yet_valid` / `invalid_claims` |
| missing / wrong registered & principal claims | 15–21 | `invalid_issuer` / `invalid_audience` / `invalid_claims` / `invalid_principal` |
| confirmation (`cnf`) shape errors | 22–24 | `unsupported_confirmation` |
| JOSE header attacks (`crit`, unknown `kid`) | 25–26 | `unsupported_critical_header` / `invalid_signature` |
| `typ` errors | 27–28 | `unexpected_typ` / `invalid_typ` |
| deeply-nested JSON (resource exhaustion) | 29 | `ok` (must not crash) |

## Regenerating

The corpus is committed output, not generated at test time. It was produced
once by a standalone script that signs with `signing_key.pem` via JOSE and
plants the raw-byte attacks the encoders would never emit. If `verify/3`'s
contract legitimately changes, regenerate the affected fixture's `.jwt`/`.json`
pair (keeping the no-trailing-newline rule) and update the `expected_error`.
Do not hand-edit a `.jwt` in place without re-deriving its signature.
