"""The bearer token a source application signs for one single request.

The verifier is `api/src/datavalv_api/authorizer.py`, and everything here is a
consequence of what it does:

* it reads `kid` out of the JOSE header to pick which registered public key to
  verify against, so the header must carry the `kid` from registration;
* it requires `exp`, `iat`, `iss`, `aud` and `jti`, with `aud` exactly
  ``datavalv`` and `iss` the client id;
* it bounds the **issued** lifetime, `exp - iat`, at 300 seconds — not the
  remaining lifetime, so a long-lived token is refused even a second before it
  expires; and
* it records every `jti` and API Gateway caches the authorizer's answer for
  zero seconds, which is what makes a token single use.

That last one is the whole reason this is a function and not a value. Four
calls need four tokens; a header hoisted into a constant reads better, passes
the first call and 403s on the second.
"""

import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

#: What `aud` must be. The authorizer compares against this literal.
AUDIENCE = "datavalv"

#: How long a minted token claims to live.
#:
#: Well under the authorizer's 300-second cap, and deliberately not near it: the
#: bound is on `exp - iat` computed from the *token's own* clock, so a source
#: server whose clock runs fast relative to ours still has room. Two minutes is
#: also longer than any one call in this client takes, which is the only thing
#: the lifetime has to cover — the token is spent on arrival either way.
LIFETIME_SECONDS = 120

PrivateKey = RSAPrivateKey | EllipticCurvePrivateKey


def algorithm_for(private_key: PrivateKey) -> str:
    """The JWS algorithm this key signs with, of the two the authorizer accepts.

    `ALGORITHMS` there is `["RS256", "ES256"]`. Registration through
    `/applications` accepts an RSA key, which is what `datavalv keygen` makes;
    EC is here because the authorizer takes it and refusing it in the client
    would be this package inventing a restriction the service does not have.
    """
    if isinstance(private_key, EllipticCurvePrivateKey):
        return "ES256"
    return "RS256"


def mint(
    *,
    client_id: str,
    key_id: str,
    private_key: PrivateKey,
    now: int | None = None,
    lifetime_seconds: int = LIFETIME_SECONDS,
) -> str:
    """Sign one token, good for one request.

    `jti` is a fresh UUID every call. Reusing one is not a smaller mistake than
    reusing a whole token: the `jti` is precisely what the authorizer records.
    """
    issued_at = int(time.time()) if now is None else now
    return jwt.encode(
        {
            "iss": client_id,
            "aud": AUDIENCE,
            "iat": issued_at,
            "exp": issued_at + lifetime_seconds,
            "jti": str(uuid.uuid4()),
        },
        private_key,
        algorithm=algorithm_for(private_key),
        headers={"kid": key_id},
    )


def authorization_header(*, client_id: str, key_id: str, private_key: PrivateKey) -> dict[str, str]:
    """A fresh `Authorization` header. Call it per request; never store it."""
    token = mint(client_id=client_id, key_id=key_id, private_key=private_key)
    return {"Authorization": f"Bearer {token}"}
