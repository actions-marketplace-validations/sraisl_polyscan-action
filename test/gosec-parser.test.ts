import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { findGoScanRoots, parseGosecSarif } from "../src/engines/gosec";

function sarifResult(ruleId: string, level: string, uri: string, line: number): unknown {
  return {
    ruleId,
    level,
    message: { text: `${ruleId} finding` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { startLine: line, startColumn: 7 },
        },
      },
    ],
  };
}

test("parseGosecSarif preserves native severity, CWE, location and module path", () => {
  const sarif = {
    runs: [
      {
        tool: {
          driver: {
            rules: [
              {
                id: "G201",
                properties: { tags: ["security", "HIGH"] },
                relationships: [{ target: { id: "89", toolComponent: { name: "CWE" } } }],
              },
            ],
          },
        },
        results: [sarifResult("G201", "error", "internal/store.go", 14)],
      },
    ],
  };

  assert.deepEqual(parseGosecSarif(sarif, "services/api"), [
    {
      engine: "gosec",
      ruleId: "G201",
      severity: "high",
      message: "G201 finding",
      file: "services/api/internal/store.go",
      line: 14,
      column: 7,
      cwe: "CWE-89",
    },
  ]);
});

test("parseGosecSarif distinguishes medium and low rule tags", () => {
  const sarif = {
    runs: [
      {
        tool: {
          driver: {
            rules: [
              { id: "G301", properties: { tags: ["security", "MEDIUM"] } },
              { id: "G104", properties: { tags: ["security", "LOW"] } },
            ],
          },
        },
        results: [
          sarifResult("G301", "error", "permissions.go", 2),
          sarifResult("G104", "warning", "errors.go", 9),
        ],
      },
    ],
  };

  assert.deepEqual(
    parseGosecSarif(sarif).map((finding) => finding.severity),
    ["medium", "low"],
  );
});

test("parseGosecSarif handles empty and incomplete reports", () => {
  assert.deepEqual(parseGosecSarif({ runs: [] }), []);
  assert.deepEqual(parseGosecSarif({}), []);
});

test("findGoScanRoots finds nested modules and ignores vendored Go files", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-gosec-test-"));
  try {
    const first = path.join(root, "services", "api");
    const second = path.join(root, "tools", "worker");
    const vendor = path.join(root, "vendor", "example");
    for (const directory of [first, second, vendor]) {
      fs.mkdirSync(directory, { recursive: true });
      fs.writeFileSync(path.join(directory, "main.go"), "package main\n");
    }
    fs.writeFileSync(path.join(first, "go.mod"), "module example/api\n");
    fs.writeFileSync(path.join(second, "go.mod"), "module example/worker\n");
    fs.writeFileSync(path.join(vendor, "go.mod"), "module ignored\n");

    assert.deepEqual(findGoScanRoots(root), [first, second]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("findGoScanRoots falls back to the target for Go files without a module", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-gosec-test-"));
  try {
    fs.writeFileSync(path.join(root, "main.go"), "package main\n");
    assert.deepEqual(findGoScanRoots(root), [root]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
