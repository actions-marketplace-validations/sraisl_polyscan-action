import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { hasWorkflows, parseZizmorSarif } from "../src/engines/zizmor";

function sarifWith(results: unknown[]): unknown {
  return { runs: [{ results }] };
}

function sarifResult(opts: {
  ruleId: string;
  level: string;
  message: string;
  uri: string;
  line: number;
  column?: number;
}): unknown {
  return {
    ruleId: opts.ruleId,
    level: opts.level,
    message: { text: opts.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: opts.uri },
          region: { startLine: opts.line, startColumn: opts.column },
        },
      },
    ],
  };
}

test("parseZizmorSarif: error level maps to high", () => {
  const sarif = sarifWith([
    sarifResult({
      ruleId: "zizmor/dangerous-triggers",
      level: "error",
      message: "pull_request_target is almost always used insecurely",
      uri: ".github/workflows/ci.yml",
      line: 2,
      column: 1,
    }),
  ]);
  const [f] = parseZizmorSarif(sarif);
  assert.equal(f.engine, "zizmor");
  assert.equal(f.ruleId, "zizmor/dangerous-triggers");
  assert.equal(f.severity, "high");
  assert.equal(f.message, "pull_request_target is almost always used insecurely");
  assert.equal(f.file, ".github/workflows/ci.yml");
  assert.equal(f.line, 2);
  assert.equal(f.column, 1);
});

test("parseZizmorSarif: warning level maps to medium", () => {
  const sarif = sarifWith([
    sarifResult({
      ruleId: "zizmor/artipacked",
      level: "warning",
      message: "does not set persist-credentials: false",
      uri: ".github/workflows/ci.yml",
      line: 9,
    }),
  ]);
  assert.equal(parseZizmorSarif(sarif)[0].severity, "medium");
});

test("parseZizmorSarif: note level maps to low", () => {
  const sarif = sarifWith([
    sarifResult({
      ruleId: "zizmor/some-informational-audit",
      level: "note",
      message: "informational",
      uri: ".github/workflows/ci.yml",
      line: 1,
    }),
  ]);
  assert.equal(parseZizmorSarif(sarif)[0].severity, "low");
});

test("parseZizmorSarif: strips the file:// scheme from the uri", () => {
  const sarif = sarifWith([
    sarifResult({
      ruleId: "zizmor/unpinned-uses",
      level: "error",
      message: "action is not pinned to a hash",
      uri: "file://.github/workflows/ci.yml",
      line: 5,
    }),
  ]);
  assert.equal(parseZizmorSarif(sarif)[0].file, ".github/workflows/ci.yml");
});

test("parseZizmorSarif: missing ruleId falls back to the engine name", () => {
  const sarif = sarifWith([
    {
      level: "warning",
      message: { text: "m" },
      locations: [
        { physicalLocation: { artifactLocation: { uri: ".github/workflows/ci.yml" }, region: { startLine: 1 } } },
      ],
    },
  ]);
  const [f] = parseZizmorSarif(sarif);
  assert.equal(f.ruleId, "zizmor");
});

test("parseZizmorSarif: multiple results all parsed", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "zizmor/artipacked", level: "warning", message: "a", uri: ".github/workflows/ci.yml", line: 1 }),
    sarifResult({ ruleId: "zizmor/dangerous-triggers", level: "error", message: "b", uri: ".github/workflows/ci.yml", line: 2 }),
    sarifResult({ ruleId: "zizmor/unpinned-uses", level: "error", message: "c", uri: ".github/workflows/release.yml", line: 3 }),
  ]);
  assert.equal(parseZizmorSarif(sarif).length, 3);
});

test("parseZizmorSarif: empty results returns empty array", () => {
  assert.deepEqual(parseZizmorSarif(sarifWith([])), []);
});

test("parseZizmorSarif: empty runs returns empty array", () => {
  assert.deepEqual(parseZizmorSarif({ runs: [] }), []);
});

test("hasWorkflows: true when .github/workflows contains a .yml or .yaml file", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-zizmor-test-"));
  try {
    const workflows = path.join(root, ".github", "workflows");
    fs.mkdirSync(workflows, { recursive: true });
    fs.writeFileSync(path.join(workflows, "ci.yml"), "on: push\njobs: {}\n");
    assert.equal(hasWorkflows(root), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("hasWorkflows: false when .github/workflows is missing", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-zizmor-test-"));
  try {
    assert.equal(hasWorkflows(root), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("hasWorkflows: false when .github/workflows has no yml/yaml files", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-zizmor-test-"));
  try {
    const workflows = path.join(root, ".github", "workflows");
    fs.mkdirSync(workflows, { recursive: true });
    fs.writeFileSync(path.join(workflows, "README.md"), "not a workflow\n");
    assert.equal(hasWorkflows(root), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
