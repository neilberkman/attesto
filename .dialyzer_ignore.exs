# Dialyzer warning suppressions. attesto is hand-written with no generated
# code, so the only entries here are deliberate fail-closed default clauses
# on the JOSE boundary. Dialyzer proves each preceding clause set is
# exhaustive *for the inferred type*, but each catch-all guards a real
# runtime gap the type does not capture:
#
#   * Attesto.Token.verify_strict_against/2 - JOSE.JWT.verify_strict wraps
#     malformed input in an internal try/catch and returns `{class, reason}`
#     shapes outside its own typespec; the `_other` clause collapses those
#     to one opaque error instead of crashing the verifier.
#   * Attesto.Token.verify_against_any/2 - propagates that opaque
#     `:invalid_token` (which Dialyzer believes cannot occur) out of the
#     key-trial loop.
#   * Attesto.Token.peek_protected_header/1 - rejects a non-binary
#     peek_protected result / decode rather than raising.
#   * Attesto.IDToken.{verify_strict_against,verify_against_any,
#     peek_protected_header} - the ID Token verifier shares the same
#     fail-closed JOSE verify-boundary clauses as Attesto.Token.
#   * Attesto.Scope.parse_resource_wildcard/2 - rejects a non-binary scope
#     rather than raising, even though callers guard is_binary upstream.
#
# These are the same class as the consuming app's documented JOSE
# verify-boundary ignores. Each is a security-relevant catch-all that must
# stay; removing it to satisfy Dialyzer would let adversarial input crash
# the verifier.
[
  {"lib/attesto/token.ex", :pattern_match},
  {"lib/attesto/token.ex", :pattern_match_cov},
  {"lib/attesto/id_token.ex", :pattern_match},
  {"lib/attesto/id_token.ex", :pattern_match_cov},
  {"lib/attesto/scope.ex", :pattern_match_cov}
]
