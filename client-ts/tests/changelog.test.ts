/**
 * `CHANGELOG.md`: what changed in each release, newest first.
 *
 * The one document a reader opens to answer "what is different since the
 * version I have", and so the one that is wrong in the most expensive way when
 * it lags: a release whose entry was never written reads as a release in which
 * nothing changed. So the top entry has to be the version this package says it
 * is, and a bump without an entry fails here rather than ships.
 */

import fs from "node:fs";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { VERSION } from "../src/index.js";

const ROOT = path.join(import.meta.dirname, "..");
const CHANGELOG = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
  files: string[];
};

/** `## 0.7.0 — 2026-10-13`: the version, and the day it was prepared. */
const entries = [...CHANGELOG.matchAll(/^## (\d+\.\d+\.\d+) — (\d{4}-\d{2}-\d{2})$/gm)].map(
  (match) => ({ version: match[1]!, date: match[2]! }),
);

function asNumbers(version: string): number[] {
  return version.split(".").map(Number);
}

function newerFirst(a: string, b: string): number {
  const [x, y] = [asNumbers(a), asNumbers(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return y[i]! - x[i]!;
  return 0;
}

describe("the changelog", () => {
  test("the newest entry is the version this package says it is", () => {
    expect(entries.length).toBeGreaterThan(0);
    expect(entries[0]!.version).toBe(VERSION);
  });

  test("every release is there once, newest first", () => {
    const versions = entries.map((entry) => entry.version);
    expect(new Set(versions).size).toBe(versions.length);
    expect(versions).toEqual([...versions].sort(newerFirst));
    // Every version ever published to npm. A changelog that starts at the
    // release it was written for says nothing about the ones before it.
    for (const published of ["0.5.0", "0.5.1", "0.6.0"]) {
      expect(versions).toContain(published);
    }
  });

  test("the dates never go forward as the versions go back", () => {
    const dates = entries.map((entry) => entry.date);
    expect(dates).toEqual([...dates].sort().reverse());
  });

  test("it ships in the package", () => {
    // npm stopped including a changelog on its own long ago; only `files`
    // puts it in the tarball, where a reader of node_modules can find it.
    expect(MANIFEST.files).toContain("CHANGELOG.md");
  });
});
