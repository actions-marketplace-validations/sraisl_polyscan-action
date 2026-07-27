import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  assertSupportedPlatform,
  cachedTool,
  sha256File,
  verifySha256,
  withTempDir,
} from "../src/tools";

test("assertSupportedPlatform accepts Linux x64 only", () => {
  assert.doesNotThrow(() => assertSupportedPlatform("linux", "x64"));
  assert.throws(() => assertSupportedPlatform("darwin", "x64"), /supports Linux x64/);
  assert.throws(() => assertSupportedPlatform("linux", "arm64"), /supports Linux x64/);
});

test("verifySha256 accepts the expected digest and rejects mismatches", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sha-"));
  const file = path.join(directory, "artifact");
  try {
    fs.writeFileSync(file, "polyscan");
    const digest = sha256File(file);
    assert.equal(digest.length, 64);
    assert.doesNotThrow(() => verifySha256(file, digest.toUpperCase()));
    assert.throws(() => verifySha256(file, "0".repeat(64)), /checksum mismatch/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("withTempDir removes temporary data after success and failure", async () => {
  let successDir = "";
  await withTempDir("polyscan-clean-", async (directory) => {
    successDir = directory;
    fs.writeFileSync(path.join(directory, "file"), "data");
  });
  assert.equal(fs.existsSync(successDir), false);

  let failureDir = "";
  await assert.rejects(
    withTempDir("polyscan-clean-", async (directory) => {
      failureDir = directory;
      throw new Error("expected");
    }),
    /expected/,
  );
  assert.equal(fs.existsSync(failureDir), false);
});

test("cachedTool installs once and reuses the cached executable", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-tool-cache-"));
  const previousCache = process.env.RUNNER_TOOL_CACHE;
  const previousTemp = process.env.RUNNER_TEMP;
  process.env.RUNNER_TOOL_CACHE = path.join(root, "cache");
  process.env.RUNNER_TEMP = path.join(root, "temp");
  fs.mkdirSync(process.env.RUNNER_TOOL_CACHE, { recursive: true });
  fs.mkdirSync(process.env.RUNNER_TEMP, { recursive: true });

  let installs = 0;
  try {
    const install = async (directory: string) => {
      installs += 1;
      fs.writeFileSync(path.join(directory, "tool"), "binary");
    };
    const name = `polyscan-test-${process.pid}-${Date.now()}`;
    const first = await cachedTool(name, "1.0.0", "tool", install);
    const second = await cachedTool(name, "1.0.0", "tool", install);
    assert.equal(first, second);
    assert.equal(installs, 1);
    assert.equal(fs.readFileSync(second, "utf8"), "binary");
  } finally {
    if (previousCache === undefined) delete process.env.RUNNER_TOOL_CACHE;
    else process.env.RUNNER_TOOL_CACHE = previousCache;
    if (previousTemp === undefined) delete process.env.RUNNER_TEMP;
    else process.env.RUNNER_TEMP = previousTemp;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
