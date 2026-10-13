/**
 * The TypeScript sample on datavalv.se/developers, compiled rather than read.
 *
 * The page is a promise somebody will act on at a terminal, and this project
 * has already shipped two samples that named things nobody could get. The
 * defence that worked for `README.md` is `readme.test.ts`: the document is the
 * source and the test is the only copy. This file does the same for the web
 * page, and the Python half of it is `client/tests/test_public_sample.py`,
 * which executes the other block on the same page against a fake Datavalv.
 *
 * **This one is type-checked**, which for TypeScript is the stronger of the
 * two. Running the sample would prove the methods exist; compiling it proves
 * the option names do — `{ retentionCount: 7 }` misspelled is an excess
 * property at compile time and a silently ignored object at run time, and a
 * vault created with the wrong retention is exactly the sort of thing nobody
 * notices until a copy they wanted is gone.
 *
 * Two things are supplied that the page cannot show and a reader has to bring:
 * `CLIENT_ID` and `KEY_ID`, which `/connect-system` step 04 hands back. They
 * are declared, not invented — declaring them is what the reader does when
 * they read them out of their own configuration.
 *
 * The import specifier is checked against `package.json` and then rewritten to
 * this checkout's `src/`, because `@datavalv/client` is not installed into its
 * own node_modules. Both halves matter: the first says the page types the name
 * the package really has, the second says the shape behind that name is the
 * one in this repository.
 */

import fs from "node:fs";
import path from "node:path";

import ts from "typescript";
import { describe, expect, test } from "vitest";

const CLIENT = path.resolve(import.meta.dirname, "..");

/** The page, in the Angular application. The sample is a literal in its source. */
const PAGE = path.resolve(
  CLIENT,
  "..",
  "web",
  "src",
  "app",
  "pages",
  "developers",
  "developers.ts",
);

const MANIFEST = JSON.parse(fs.readFileSync(path.join(CLIENT, "package.json"), "utf8")) as {
  name: string;
};

/**
 * Every `<pre class="pub-code …">` block on the page, as a reader sees it.
 *
 * The blocks are syntax-highlighted with `<span>`s and carry HTML entities —
 * a brace would open an ICU expansion in an Angular template and a bare `@`
 * would open a control-flow block — so the markup is removed and the entities
 * are decoded. What comes back is the text on screen, which is the text
 * somebody copies.
 */
function codeBlocks(page: string): string[] {
  const blocks = [...page.matchAll(/<pre\b[^>]*class="pub-code[^"]*"[^>]*>(.*?)<\/pre>/gs)];
  return blocks.map((match) => unescapeHtml(match[1]!.replaceAll(/<[^>]+>/g, "")));
}

function unescapeHtml(text: string): string {
  return text
    .replaceAll(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number(code)))
    .replaceAll("&quot;", '"')
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

const SAMPLES = codeBlocks(fs.readFileSync(PAGE, "utf8")).filter((block) =>
  block.includes("DatavalvClient"),
);

/** The block that imports the package, as opposed to the Python one beside it. */
const SAMPLE = SAMPLES.find((block) => block.includes("import {"));

describe("the TypeScript sample on /developers", () => {
  test("the page still shows one", () => {
    // The guard under the guard. Every assertion below is about a block of
    // code, so a page that had lost it — or gone back to raw HTTP, which
    // imports nothing — would make them all pass by having nothing to compile.
    expect(SAMPLE, `${path.basename(PAGE)} shows no TypeScript sample`).toBeDefined();
    expect(SAMPLE).toContain("client.pushBackup(");
  });

  test("it imports the name this package is published under", () => {
    // Not "a plausible name": the specifier a reader types has to be the one
    // `package.json` declares, or the import fails for everybody we hand the
    // tarball to. Rename the package and this fails until the page is retyped.
    expect(SAMPLE).toContain(`from "${MANIFEST.name}"`);
  });

  test("it compiles against this client, under this package's own settings", () => {
    // The whole point of the file. `tsconfig.json` is read rather than
    // restated, so the sample is held to the same strictness as `src/` — and
    // a diagnostic here names the line of the page that caused it.
    //
    // Joined into one string rather than compared as an array: a failing
    // `toEqual([])` prints "Array(1)" and the message is the whole value of
    // the test.
    expect(checkSample(SAMPLE!).join("\n")).toBe("");
  });
});

/** Where the sample is compiled from, so `../src/index.js` resolves. */
const VIRTUAL = path.join(CLIENT, "tests", "__public-sample__.ts");

/**
 * The two values `/connect-system` step 04 issues. The page shows them as bare
 * identifiers, which is what a reader's own configuration will supply.
 */
const PREAMBLE = ["declare const CLIENT_ID: string;", "declare const KEY_ID: string;", ""].join(
  "\n",
);

function checkSample(sample: string): string[] {
  const source = PREAMBLE + sample.replace(`"${MANIFEST.name}"`, '"../src/index.js"');
  const offset = PREAMBLE.split("\n").length - 1;

  const configPath = path.join(CLIENT, "tsconfig.json");
  const { config } = ts.readConfigFile(configPath, ts.sys.readFile);
  const { options } = ts.parseJsonConfigFileContent(config, ts.sys, CLIENT, undefined, configPath);

  // A compiler host that serves one file from memory and everything else from
  // disk. Nothing is written: a temp file inside the package would be picked
  // up by a watcher, and one outside it would resolve neither `node:fs` nor
  // the client beside it.
  const host = ts.createCompilerHost({ ...options, noEmit: true }, true);
  const readFile = host.readFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  const getSourceFile = host.getSourceFile.bind(host);

  host.readFile = (name) => (isVirtual(name) ? source : readFile(name));
  host.fileExists = (name) => isVirtual(name) || fileExists(name);
  host.getSourceFile = (name, languageVersion, ...rest) =>
    isVirtual(name)
      ? ts.createSourceFile(name, source, languageVersion, true)
      : getSourceFile(name, languageVersion, ...rest);

  const program = ts.createProgram([VIRTUAL], { ...options, noEmit: true }, host);

  return ts.getPreEmitDiagnostics(program).map((diagnostic) => {
    const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, " ");
    if (diagnostic.file === undefined || diagnostic.start === undefined) return message;
    const { line } = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
    const where = isVirtual(diagnostic.file.fileName)
      ? `the sample, line ${line + 1 - offset}`
      : path.relative(CLIENT, diagnostic.file.fileName);
    return `${where}: ${message}`;
  });
}

function isVirtual(name: string): boolean {
  return path.resolve(name) === VIRTUAL;
}
