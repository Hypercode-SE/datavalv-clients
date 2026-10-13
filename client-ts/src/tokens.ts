/**
 * The bearer token a source application signs for one single request.
 *
 * The verifier is `api/src/datavalv_api/authorizer.py`, and everything here is a
 * consequence of what it does:
 *
 * * it reads `kid` out of the JOSE header to pick which registered public key
 *   to verify against, so the header must carry the `kid` from registration;
 * * it requires `exp`, `iat`, `iss`, `aud` and `jti`, with `aud` exactly
 *   `datavalv` and `iss` the client id;
 * * it bounds the **issued** lifetime, `exp - iat`, at 300 seconds — not the
 *   remaining lifetime, so a long-lived token is refused even a second before
 *   it expires; and
 * * it records every `jti` and API Gateway caches the authorizer's answer for
 *   zero seconds, which is what makes a token single use.
 *
 * That last one is the whole reason this is a function and not a value. Four
 * calls need four tokens; a header hoisted into a constant reads better, passes
 * the first call and 403s on the second.
 *
 * ## Why `jose` and not `jsonwebtoken`
 *
 * `jose` is ESM-native with **zero runtime dependencies**, and signs with a
 * Node `KeyObject` directly. This package exists to be installed on somebody
 * else's backup server and handed their private signing key; every transitive
 * dependency in that path is another package that would be in a position to
 * read it. `jsonwebtoken` is CommonJS and brings `jws`, `jwa`, `safe-buffer`,
 * `ecdsa-sig-formatter` and half a dozen `lodash.*` packages with it — a larger
 * surface for no behaviour this client needs.
 */

import { createPrivateKey, randomUUID, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";

/** What `aud` must be. The authorizer compares against this literal. */
export const AUDIENCE = "datavalv";

/**
 * How long a minted token claims to live.
 *
 * Well under the authorizer's 300-second cap, and deliberately not near it: the
 * bound is on `exp - iat` computed from the *token's own* clock, so a source
 * server whose clock runs fast relative to ours still has room. Two minutes is
 * also longer than any one call in this client takes, which is the only thing
 * the lifetime has to cover — the token is spent on arrival either way.
 */
export const LIFETIME_SECONDS = 120;

/**
 * The JWS algorithm this key signs with, of the two the authorizer accepts.
 *
 * `ALGORITHMS` there is `["RS256", "ES256"]`. Registration through
 * `/applications` accepts an RSA key, which is what `datavalv keygen` makes; EC
 * is here because the authorizer takes it and refusing it in the client would
 * be this package inventing a restriction the service does not have.
 */
export function algorithmFor(privateKey: KeyObject): "RS256" | "ES256" {
  return privateKey.asymmetricKeyType === "ec" ? "ES256" : "RS256";
}

/**
 * A signing key from PEM text, or a `KeyObject` straight through.
 *
 * Node parses the PEM here rather than at first use, so an unusable key is a
 * `ConfigurationError` before any request is made rather than a signing failure
 * part-way through a push.
 */
export function loadSigningKey(privateKey: string | KeyObject): KeyObject {
  return typeof privateKey === "string" ? createPrivateKey(privateKey) : privateKey;
}

export interface MintOptions {
  clientId: string;
  keyId: string;
  privateKey: KeyObject;
  /** Seconds since the epoch. The tests pin it; nothing else passes it. */
  now?: number;
  lifetimeSeconds?: number;
}

/**
 * Sign one token, good for one request.
 *
 * `jti` is a fresh UUID every call. Reusing one is not a smaller mistake than
 * reusing a whole token: the `jti` is precisely what the authorizer records.
 */
export async function mint(options: MintOptions): Promise<string> {
  const issuedAt = options.now ?? Math.floor(Date.now() / 1000);
  const lifetime = options.lifetimeSeconds ?? LIFETIME_SECONDS;
  return new SignJWT({})
    .setProtectedHeader({ alg: algorithmFor(options.privateKey), kid: options.keyId })
    .setIssuer(options.clientId)
    .setAudience(AUDIENCE)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + lifetime)
    .setJti(randomUUID())
    .sign(options.privateKey);
}

/** A fresh `Authorization` header. Call it per request; never store it. */
export async function authorizationHeader(options: {
  clientId: string;
  keyId: string;
  privateKey: KeyObject;
}): Promise<Record<string, string>> {
  return { Authorization: `Bearer ${await mint(options)}` };
}
