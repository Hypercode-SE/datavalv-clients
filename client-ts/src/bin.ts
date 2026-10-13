#!/usr/bin/env node
/**
 * The `datavalv` command's entry point, and nothing else.
 *
 * Separate from `cli.ts` so that `main` can be imported and called by the tests
 * without the module deciding, from `process.argv`, that it is being run. The
 * usual `import.meta.url === process.argv[1]` guard is not reliable here: npm
 * installs `bin` as a symlink in `node_modules/.bin`, and the two paths are the
 * same file under different names.
 */

import { main } from "./cli.js";

// `process.exitCode` rather than `process.exit()`: `process.exit()` does not
// wait for a pending stdout write to flush when stdout is a pipe, so the backup
// id `BACKUP=$(datavalv push …)` is meant to capture can be lost.
main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    // Anything that reached here is a defect in this client rather than a
    // failure it understands. Print it whole — a stack trace in the cron mail
    // is what makes it reportable.
    console.error(error);
    process.exitCode = 1;
  },
);
