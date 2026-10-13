/**
 * The invite key.
 *
 * An invitation carries the tenant private key wrapped under a symmetric key,
 * so that accepting it hands the invitee the vault without the operator ever
 * holding a value that opens it. That wrapping key is *derived* from the
 * 256-bit invite secret rather than being it.
 *
 * The reason is the one that also makes the Cognito login hash a derivation of
 * the password rather than the password: the value that travels must not be
 * the value that decrypts. The invite secret rides in a URL fragment — never
 * sent to a server, but sitting in the invitee's address bar, in their browser
 * history, and in whatever chat message or email carried the link. One HKDF
 * step between that value and the vault means a leaked fragment is not itself
 * a key.
 */

import type { Bytes } from "./crypto.js";
import { hkdf } from "./derive.js";
import { AES_KEY_BITS, HKDF_INFO } from "./formatConstants.js";

/**
 * The key an invite's tenant-key wrapping is done under.
 *
 * `secret` is the raw 256-bit invite secret, before whatever rendering it is
 * given for the URL fragment. The output is an AES-256 key, so its length
 * comes from the frozen spec rather than from a literal here.
 */
export async function deriveInviteKey(secret: Bytes): Promise<Bytes> {
  return hkdf(secret, HKDF_INFO.invite, AES_KEY_BITS / 8);
}
