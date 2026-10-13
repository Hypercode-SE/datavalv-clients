/**
 * A real HTTP server standing in for Datavalv and for S3.
 *
 * `fakeDatavalv.ts` intercepts `fetch` and is enough for everything that is
 * about this client's own behaviour. This one listens on a socket, because the
 * interop test has to run a client written in another language against it —
 * there is no `fetch` to intercept in a Python subprocess, and the whole value
 * of that test is that neither side is a stand-in.
 *
 * Listening also makes two things observable that a `fetch` double cannot see:
 * the `Content-Length` the runtime put on the upload, which `presigned_put`
 * signs, and the exact bytes on the wire.
 */

import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AddressInfo } from "node:net";
import { decodeJwt, decodeProtectedHeader, importSPKI, jwtVerify } from "jose";

export interface RecordedCall {
  method: string;
  path: string;
  headers: Record<string, string | undefined>;
  body: Buffer;
  token: string | undefined;
}

export interface StubState {
  /** The vault key a push is encrypted to. Set per direction. */
  tenantPublicPem: string;
  tenantKeyId: string;
  /** Verified against, so a token that does not verify is a 403 here too. */
  signingPublicPem: string;
  clientId: string;
  keyId: string;
  externalId: string;
  backupId: string;
}

export class StubService {
  readonly calls: RecordedCall[] = [];
  readonly seenJtis = new Set<string>();
  uploaded: Buffer | undefined;
  registered: Record<string, unknown> | undefined;
  uploadCall: RecordedCall | undefined;

  #server: Server | undefined;

  constructor(readonly state: StubState) {}

  async listen(): Promise<string> {
    this.#server = createServer((request, response) => {
      void this.#handle(request, response);
    });
    await new Promise<void>((resolve) => this.#server!.listen(0, "127.0.0.1", resolve));
    const { port } = this.#server!.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }

  /** Always called from an `afterAll`: a listening socket outlives the run. */
  async close(): Promise<void> {
    const server = this.#server;
    if (!server) return;
    this.#server = undefined;
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);

    const authorization = request.headers["authorization"];
    const call: RecordedCall = {
      method: request.method ?? "GET",
      path: (request.url ?? "/").split("?")[0] ?? "/",
      headers: request.headers as Record<string, string | undefined>,
      body: Buffer.concat(chunks),
      token: authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined,
    };
    this.calls.push(call);

    if (call.path.startsWith("/upload/")) {
      this.#upload(call, response);
      return;
    }

    const denial = await this.#verify(call);
    if (denial) {
      reply(response, denial, { message: "Forbidden" });
      return;
    }
    this.#route(call, response);
  }

  async #verify(call: RecordedCall): Promise<number | undefined> {
    if (call.token === undefined) return 401;
    try {
      if (decodeProtectedHeader(call.token).kid !== this.state.keyId) return 403;
      const key = await importSPKI(this.state.signingPublicPem, "RS256");
      const { payload } = await jwtVerify(call.token, key, {
        audience: "datavalv",
        issuer: this.state.clientId,
        requiredClaims: ["exp", "iat", "iss", "aud", "jti"],
      });
      if (Number(payload.exp) - Number(payload.iat) > 300) return 403;
      const jti = String(payload.jti);
      // The single-use rule, enforced across the language boundary as well:
      // the Python client must mint one token per call or this answers 403.
      if (this.seenJtis.has(jti)) return 403;
      this.seenJtis.add(jti);
      return undefined;
    } catch {
      return 403;
    }
  }

  #upload(call: RecordedCall, response: ServerResponse): void {
    this.uploadCall = call;
    if (call.headers["authorization"]) {
      // S3 refuses a presigned request that also carries an Authorization
      // header: two sets of credentials on one request.
      response.writeHead(400).end("<Error><Code>InvalidArgument</Code></Error>");
      return;
    }
    const checksum = call.headers["x-amz-checksum-sha256"];
    if (!checksum) {
      response.writeHead(403).end("<Error><Code>SignatureDoesNotMatch</Code></Error>");
      return;
    }
    if (!createHash("sha256").update(call.body).digest().equals(Buffer.from(checksum, "base64"))) {
      response.writeHead(400).end("<Error><Code>BadDigest</Code></Error>");
      return;
    }
    this.uploaded = call.body;
    response.writeHead(200, { "x-amz-checksum-sha256": checksum }).end();
  }

  #route(call: RecordedCall, response: ServerResponse): void {
    const { externalId, backupId } = this.state;

    if (call.method === "GET" && call.path === `/v1/tenants/${externalId}/public-key`) {
      reply(response, 200, {
        tenantId: "t-1",
        keyId: this.state.tenantKeyId,
        publicKeyPem: this.state.tenantPublicPem,
      });
      return;
    }
    if (call.method === "POST" && call.path === `/v1/tenants/${externalId}/backups`) {
      this.registered = JSON.parse(call.body.toString("utf8")) as Record<string, unknown>;
      reply(response, 201, {
        backupId,
        uploadUrl: `${this.origin()}/upload/${backupId}`,
        expiresIn: 900,
      });
      return;
    }
    if (call.method === "POST" && call.path === `/v1/backups/${backupId}/complete`) {
      reply(response, 200, { status: "available", pruned: 0 });
      return;
    }
    reply(response, 404, { code: "not_found", detail: call.path });
  }

  origin(): string {
    const { port } = this.#server!.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }
}

function reply(response: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  response.writeHead(status, { "content-type": "application/json" }).end(text);
}

/** The `jti`s a run used, for the "one token per call" assertion. */
export function jtisOf(calls: RecordedCall[]): string[] {
  return calls
    .map((call) => call.token)
    .filter((token): token is string => token !== undefined)
    .map((token) => String(decodeJwt(token).jti));
}
