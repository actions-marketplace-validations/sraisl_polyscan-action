import test from "node:test";
import assert from "node:assert/strict";

import { parseTrufflehogSarif } from "../src/engines/trufflehog";

const ABS = "/repo";

function sarifWith(results: unknown[]): unknown {
  return { runs: [{ results }] };
}

function sarifResult(opts: { ruleId: string; level: string; message: string; uri: string; line: number }): unknown {
  return {
    ruleId: opts.ruleId,
    level: opts.level,
    message: { text: opts.message },
    locations: [
      { physicalLocation: { artifactLocation: { uri: opts.uri }, region: { startLine: opts.line } } },
    ],
  };
}

test("parseTrufflehogSarif: error level (verified secret) maps to critical", () => {
  const sarif = sarifWith([
    sarifResult({
      ruleId: "AWS",
      level: "error",
      message: "Found verified result for detector AWS.",
      uri: `${ABS}/config.py`,
      line: 3,
    }),
  ]);
  const [f] = parseTrufflehogSarif(sarif, ABS);
  assert.equal(f.engine, "trufflehog");
  assert.equal(f.ruleId, "AWS");
  assert.equal(f.severity, "critical");
  assert.equal(f.message, "Found verified result for detector AWS.");
  assert.equal(f.file, "config.py");
  assert.equal(f.line, 3);
});

test("parseTrufflehogSarif: warning level (unverified) maps to high", () => {
  const sarif = sarifWith([
    sarifResult({
      ruleId: "PrivateKey",
      level: "warning",
      message: "Found unverified result for detector PrivateKey.",
      uri: `${ABS}/id_rsa`,
      line: 1,
    }),
  ]);
  assert.equal(parseTrufflehogSarif(sarif, ABS)[0].severity, "high");
});

test("parseTrufflehogSarif: any other/missing level defensively maps to high, not low", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "Generic", level: "note", message: "m", uri: `${ABS}/f.txt`, line: 1 }),
  ]);
  assert.equal(parseTrufflehogSarif(sarif, ABS)[0].severity, "high");
});

test("parseTrufflehogSarif: strips the file:// scheme and abs prefix from the uri", () => {
  const sarif = sarifWith([
    sarifResult({
      ruleId: "Slack",
      level: "warning",
      message: "Found unverified result for detector Slack.",
      uri: `file://${ABS}/services/api/config.py`,
      line: 7,
    }),
  ]);
  assert.equal(parseTrufflehogSarif(sarif, ABS)[0].file, "services/api/config.py");
});

test("parseTrufflehogSarif: missing ruleId falls back to the engine name", () => {
  const sarif = sarifWith([
    { level: "warning", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: `${ABS}/f` }, region: { startLine: 1 } } }] },
  ]);
  assert.equal(parseTrufflehogSarif(sarif, ABS)[0].ruleId, "trufflehog");
});

test("parseTrufflehogSarif: multiple results all parsed", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "AWS", level: "error", message: "a", uri: `${ABS}/a.py`, line: 1 }),
    sarifResult({ ruleId: "PrivateKey", level: "warning", message: "b", uri: `${ABS}/b.py`, line: 2 }),
  ]);
  assert.equal(parseTrufflehogSarif(sarif, ABS).length, 2);
});

test("parseTrufflehogSarif: empty results returns empty array", () => {
  assert.deepEqual(parseTrufflehogSarif(sarifWith([]), ABS), []);
});

test("parseTrufflehogSarif: empty runs returns empty array", () => {
  assert.deepEqual(parseTrufflehogSarif({ runs: [] }, ABS), []);
});
