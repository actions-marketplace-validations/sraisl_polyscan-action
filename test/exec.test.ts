import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { resolveExecutable, resolvePinnedExecutable } from "../src/exec";

test("resolveExecutable returns an absolute executable from the supplied PATH", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-path-"));
  const executable = path.join(directory, "semgrep");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\n");
    fs.chmodSync(executable, 0o755);

    assert.equal(resolveExecutable("semgrep", directory), executable);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolveExecutable ignores tools outside the inherited PATH", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-path-"));
  const executable = path.join(directory, "semgrep");
  const inheritedPath = path.join(directory, "empty");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\n");
    fs.chmodSync(executable, 0o755);
    fs.mkdirSync(inheritedPath);

    assert.equal(resolveExecutable("semgrep", inheritedPath), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolveExecutable rejects non-executable files", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-path-"));
  const executable = path.join(directory, "semgrep");
  try {
    fs.writeFileSync(executable, "not executable");
    fs.chmodSync(executable, 0o644);

    assert.equal(resolveExecutable("semgrep", directory), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolvePinnedExecutable accepts only the expected tool version", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-version-"));
  const executable = path.join(directory, "opengrep");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\nprintf '1.26.0\\n'\n");
    fs.chmodSync(executable, 0o755);

    assert.equal(
      await resolvePinnedExecutable(
        "opengrep",
        "1.26.0",
        ["--version", "--disable-version-check"],
        directory,
      ),
      executable,
    );
    assert.equal(
      await resolvePinnedExecutable("opengrep", "1.25.0", ["--version"], directory),
      null,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolvePinnedExecutable rejects malformed output and failed version commands", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-version-"));
  const executable = path.join(directory, "opengrep");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\nprintf 'unknown\\n'\n");
    fs.chmodSync(executable, 0o755);
    assert.equal(
      await resolvePinnedExecutable("opengrep", "1.26.0", ["--version"], directory),
      null,
    );

    fs.writeFileSync(executable, "#!/bin/sh\nexit 2\n");
    assert.equal(
      await resolvePinnedExecutable("opengrep", "1.26.0", ["--version"], directory),
      null,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
