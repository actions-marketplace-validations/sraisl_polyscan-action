import test from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

const SCRIPT = path.resolve(__dirname, "../../scripts/engine-tools.mjs");

function runCli(args: string[]) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: "utf8",
    env: process.env,
  });
}

test("engine tools list prints every locked tool", () => {
  const result = runCli(["list"]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^tool\tprovider\tversion/m);
  assert.match(result.stdout, /^gosec\tgithub\t2\.28\.0$/m);
  assert.match(result.stdout, /^semgrep\tpypi\t1\.170\.0$/m);
  assert.match(result.stdout, /^trivy\tgithub\t0\.72\.0$/m);
});

test("engine tools list rejects unknown tools", () => {
  const result = runCli(["list", "unknown"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unknown tool "unknown"/);
});

test("engine tools update rejects unsafe versions before network access", () => {
  const result = runCli(["update", "trivy", "../../bad", "--dry-run"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /invalid version/);
});

test("engine tools update rejects unknown options", () => {
  const result = runCli(["update", "trivy", "1.2.3", "--unsafe"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unknown option "--unsafe"/);
});
