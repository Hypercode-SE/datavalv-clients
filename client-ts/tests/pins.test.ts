/**
 * The key a backup is encrypted to, and whose word it is taken on.
 *
 * Step 1 of a push asks the service for the vault's public key, and the service
 * is the one party this design does not trust with plaintext: a server that
 * answered with a key of its own would read every backup from then on, and
 * nothing in the protocol could show it. So the client remembers the
 * fingerprint of the key it was first given for each vault, and refuses --
 * before encrypting anything -- if a later answer is a different key. A vault's
 * key never changes.
 *
 * The same tests as `client/tests/test_pins.py`, because it is the same rule.
 */
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import { generateKeypair, publicKeyFingerprint } from "@datavalv/crypto";

import { DatavalvClient } from "../src/client.js";
import { ConfigurationError, VaultKeyChanged } from "../src/errors.js";
import { FilePins, type KeyPins, MemoryPins } from "../src/pins.js";
import {
  API_BASE,
  CLIENT_ID,
  EXTERNAL_ID,
  FOUR_CALLS,
  FakeDatavalv,
  KEY_ID,
} from "./support/fakeDatavalv.js";
import { signingKey, tenantKey } from "./support/fixtures.js";

const PLAINTEXT = new Uint8Array(Buffer.from("medlemsregister"));

function service(): FakeDatavalv {
  return new FakeDatavalv({
    signingPublicPem: signingKey.publicKeyPem,
    tenantPublicPem: tenantKey.publicKeyPem,
  });
}

function makeClient(fake: FakeDatavalv, pins?: KeyPins): DatavalvClient {
  return new DatavalvClient({
    apiBase: API_BASE,
    clientId: CLIENT_ID,
    keyId: KEY_ID,
    privateKey: signingKey.privateKeyPem,
    fetch: fake.fetch,
    ...(pins === undefined ? {} : { pins }),
  });
}

function scratch(): string {
  return join(mkdtempSync(join(tmpdir(), "datavalv-pins-test-")), "pins.json");
}

describe("pinning", () => {
  test("the first push records the key and says so", async () => {
    const pins = new MemoryPins();
    const pushed = await makeClient(service(), pins).pushBackup(EXTERNAL_ID, PLAINTEXT);

    const expected = await publicKeyFingerprint(tenantKey.publicKeyPem);
    expect(pushed.keyFingerprint).toBe(expected);
    expect(pushed.keyFirstSeen).toBe(true);
    expect(pins.get(API_BASE, CLIENT_ID, EXTERNAL_ID)).toBe(expected);
  });

  test("a later push to the same key is not a first sighting", async () => {
    const pins = new MemoryPins();
    const fake = service();
    await makeClient(fake, pins).pushBackup(EXTERNAL_ID, PLAINTEXT);
    const again = await makeClient(fake, pins).pushBackup(EXTERNAL_ID, PLAINTEXT);

    expect(again.keyFirstSeen).toBe(false);
  });

  test("a different key is refused before anything is encrypted or sent", async () => {
    // The attack, from the client's side. The service answers step 1 with a
    // key that is not the one this machine has seen for this vault. Whatever
    // the reason, encrypting to it is the one thing that must not happen, so
    // the push stops after that single GET: no copy registered, nothing
    // uploaded.
    const pins = new MemoryPins();
    const fake = service();
    await makeClient(fake, pins).pushBackup(EXTERNAL_ID, PLAINTEXT);

    const substituted = (await generateKeypair()).publicKeyPem;
    fake.tenantPublicPem = substituted;
    fake.calls.length = 0;
    fake.uploaded = undefined;

    const refusal = await makeClient(fake, pins)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((error: unknown) => error);

    expect(refusal).toBeInstanceOf(VaultKeyChanged);
    const error = refusal as VaultKeyChanged;
    expect(fake.calls.map((call) => call.step)).toEqual([FOUR_CALLS[0]]);
    expect(fake.uploaded).toBeUndefined();
    expect(error.retryable).toBe(false);
    expect(error.pinned).toBe(await publicKeyFingerprint(tenantKey.publicKeyPem));
    expect(error.offered).toBe(await publicKeyFingerprint(substituted));
    expect(error.message).toContain(error.pinned);
    expect(error.message).toContain(error.offered);
    expect(error.message).toContain(EXTERNAL_ID);
    // The pin is not moved by a refusal. A client that re-pinned on a mismatch
    // would refuse once and then comply.
    expect(pins.get(API_BASE, CLIENT_ID, EXTERNAL_ID)).toBe(error.pinned);
  });

  test("a pin belongs to one vault of one application on one API", async () => {
    const pins = new MemoryPins();
    pins.set(API_BASE, CLIENT_ID, "another-vault", "0".repeat(64));
    pins.set("https://api.datavalv.se", CLIENT_ID, EXTERNAL_ID, "1".repeat(64));
    pins.set(API_BASE, "another-client", EXTERNAL_ID, "2".repeat(64));

    const pushed = await makeClient(service(), pins).pushBackup(EXTERNAL_ID, PLAINTEXT);
    expect(pushed.keyFirstSeen).toBe(true);
  });

  test("pins can be given in advance, for a machine with no disk to remember on", async () => {
    const expected = await publicKeyFingerprint(tenantKey.publicKeyPem);
    const right = new MemoryPins([[[API_BASE, CLIENT_ID, EXTERNAL_ID], expected]]);
    const wrong = new MemoryPins([[[API_BASE, CLIENT_ID, EXTERNAL_ID], "f".repeat(64)]]);

    expect((await makeClient(service(), right).pushBackup(EXTERNAL_ID, PLAINTEXT)).keyFirstSeen).toBe(
      false,
    );
    await expect(makeClient(service(), wrong).pushBackup(EXTERNAL_ID, PLAINTEXT)).rejects.toBeInstanceOf(
      VaultKeyChanged,
    );
  });
});

describe("the pin file", () => {
  test("pins are remembered on disk by default", async () => {
    // As `known_hosts` is: a second *process* has to refuse a changed key, and
    // that is every scheduled push after the first.
    const fake = service();
    const first = await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);
    const second = await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);

    expect([first.keyFirstSeen, second.keyFirstSeen]).toEqual([true, false]);
    expect(existsSync(process.env["DATAVALV_KNOWN_VAULTS"]!)).toBe(true);
  });

  test("it survives a new client and refuses a changed key", async () => {
    const path = scratch();
    const fake = service();
    await makeClient(fake, new FilePins(path)).pushBackup(EXTERNAL_ID, PLAINTEXT);

    fake.tenantPublicPem = (await generateKeypair()).publicKeyPem;
    await expect(
      makeClient(fake, new FilePins(path)).pushBackup(EXTERNAL_ID, PLAINTEXT),
    ).rejects.toBeInstanceOf(VaultKeyChanged);
  });

  test("it is private, and its directory is made", () => {
    const path = join(mkdtempSync(join(tmpdir(), "datavalv-pins-test-")), "state", "datavalv", "kv.json");
    new FilePins(path).set(API_BASE, CLIENT_ID, EXTERNAL_ID, "a".repeat(64));

    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(path, "..")).mode & 0o777).toBe(0o700);
  });

  test("it is the same file the Python client writes", () => {
    // One machine may run either client, or both. The format is stated here
    // and in `client/tests/test_pins.py`, character for character.
    const path = scratch();
    new FilePins(path).set(API_BASE, CLIENT_ID, EXTERNAL_ID, "a".repeat(64));

    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({
      version: 1,
      vaults: { [`${API_BASE} ${CLIENT_ID} ${EXTERNAL_ID}`]: { fingerprint: "a".repeat(64) } },
    });
  });

  test("a file that cannot be read as one stops the push", async () => {
    // Treating a corrupt file as an empty one would turn "somebody damaged the
    // pin file" into "every key is new, carry on" -- the attack with one extra
    // step.
    const path = scratch();
    writeFileSync(path, "{ not json");
    const fake = service();

    await expect(
      makeClient(fake, new FilePins(path)).pushBackup(EXTERNAL_ID, PLAINTEXT),
    ).rejects.toBeInstanceOf(ConfigurationError);
    expect(fake.uploaded).toBeUndefined();
  });

  test("a pin can be forgotten after a person has checked why it changed", () => {
    const pins = new FilePins(scratch());
    pins.set(API_BASE, CLIENT_ID, EXTERNAL_ID, "a".repeat(64));
    pins.forget(API_BASE, CLIENT_ID, EXTERNAL_ID);
    expect(pins.get(API_BASE, CLIENT_ID, EXTERNAL_ID)).toBeUndefined();
  });
});
