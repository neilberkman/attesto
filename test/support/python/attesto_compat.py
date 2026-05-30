"""Reference Python primitives for the Attesto cross-language parity tests.

Driven in-process from the BEAM via `erlang_python` (the `:py` NIF), the
same bridge approach the surrounding test suite uses elsewhere. Each
function takes plain bindings (the Elixir side passes binaries and maps,
which arrive as Python `bytes`/`dict`) and returns plain data (str / int /
dict / tuple) so the result decodes straight back to Elixir terms.

Two independent reference implementations underpin the JWT-verify leg so
parity is not merely round-tripping one library's own canonicalisation:

  - `joserfc` is the high-level RFC stack (RS256 JWT verify, EC keys,
    RFC 7638 thumbprints, ES256 DPoP proofs).
  - `cryptography` is used directly (raw RSA-PKCS1v15-SHA256 verify plus a
    hand-rolled JWT decode) as a second, decode-independent check.

Required importable packages in the active interpreter: `joserfc`,
`cryptography`.
"""

import base64
import hashlib
import json
import os

from joserfc import jwt as jose_jwt
from joserfc.jwk import ECKey, RSAKey

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _s(v):
    """`erlang_python` hands Elixir binaries over as Python `bytes`. The
    reference libraries want `str` keys/values (and the verifiers compare
    `iss`/`aud`, which are `str`). Normalise every value crossing the
    boundary back to `str`, recursing into dict keys/values so a
    round-tripped JWK re-imports cleanly."""
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8")
    if isinstance(v, dict):
        return {_s(k): _s(val) for k, val in v.items()}
    return v


def _b64url_nopad(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment):
    segment = _s(segment)
    padding_len = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding_len)


def generate_pkce_pair():
    """Generate a fresh PKCE `code_verifier` (RFC 7636 §4.1: 43..128
    unreserved characters) and its `S256` `code_challenge`
    (base64url(SHA-256(verifier)), no padding), exactly as a real client
    library would. Returns `(verifier, challenge)` as plain str."""
    verifier = _b64url_nopad(os.urandom(32))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = _b64url_nopad(digest)
    return (verifier, challenge)


def joserfc_verify_rs256(token, public_pem):
    """Verify an RS256 JWT with joserfc against an RSA public PEM and
    return the decoded claims as a plain dict."""
    key = RSAKey.import_key(_s(public_pem))
    decoded = jose_jwt.decode(_s(token), key, algorithms=["RS256"])
    return dict(decoded.claims)


def cryptography_verify_rs256(token, public_pem, issuer, audience):
    """Verify the same RS256 JWT with `cryptography` directly: split the
    compact JWS, verify the RSA-PKCS1v15-SHA256 signature over the signing
    input, decode the claims by hand, and enforce `iss`/`aud`. This shares
    no JWT-decode code with joserfc, so agreement between the two is a
    genuine cross-implementation check rather than one library validating
    its own output. Raises on a bad signature or an `iss`/`aud` mismatch
    (surfacing to Elixir as a test error). Returns the claims dict."""
    token = _s(token)
    header_b64, payload_b64, signature_b64 = token.split(".")
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    signature = _b64url_decode(signature_b64)

    public_key = serialization.load_pem_public_key(_s(public_pem).encode("ascii"))
    # Raises cryptography.exceptions.InvalidSignature on a forged token.
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    claims = json.loads(_b64url_decode(payload_b64))

    if claims.get("iss") != _s(issuer):
        raise ValueError("iss mismatch: %r != %r" % (claims.get("iss"), _s(issuer)))

    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if _s(audience) not in auds:
        raise ValueError("aud mismatch: %r not in %r" % (_s(audience), auds))

    return claims


def joserfc_jwk_thumbprint(jwk_dict):
    """RFC 7638 SHA-256 thumbprint of an EC public JWK, as joserfc computes
    it. `jwk_dict` carries only public members (`kty`/`crv`/`x`/`y`)."""
    key = ECKey.import_key(_s(jwk_dict))
    return key.thumbprint()


def generate_ec256_public_jwk():
    """Generate a fresh EC P-256 key and return ONLY its public JWK members
    (`kty`/`crv`/`x`/`y`) as a plain dict."""
    key = ECKey.generate_key(crv="P-256")
    return dict(key.as_dict(private=False))


def build_es256_dpop_proof(htm, htu, iat, jti):
    """Generate a fresh EC P-256 key in Python and sign a DPoP proof JWS
    (RFC 9449 §4) with it: header carries `typ: dpop+jwt`, `alg: ES256`, and
    the embedded PUBLIC jwk; payload carries `htm`/`htu`/`iat`/`jti`.

    Returns `(proof_compact, public_jwk_dict, thumbprint)` so the Elixir
    side can feed the proof to Attesto and assert the verified `jkt` equals
    Python's own RFC 7638 thumbprint of the signing key."""
    key = ECKey.generate_key(crv="P-256")
    public_jwk = dict(key.as_dict(private=False))

    header = {
        "alg": "ES256",
        "jwk": public_jwk,
        "typ": "dpop+jwt",
    }
    claims = {
        "htm": _s(htm),
        "htu": _s(htu),
        "iat": int(iat),
        "jti": _s(jti),
    }
    proof = jose_jwt.encode(header, claims, key, algorithms=["ES256"])
    return (proof, public_jwk, key.thumbprint())
