import test from "node:test";
import assert from "node:assert/strict";

import { renderSummary } from "../src/summary";
import { countBySeverity, EngineResult, Finding } from "../src/schema";
import { evaluateGate } from "../src/gate";

test("renderSummary shows engine states and escapes dynamic table content", () => {
  const findings: Finding[] = [
    {
      engine: "semgrep",
      ruleId: "rule|id",
      severity: "high",
      message: "first line\nsecond | line",
      file: "src/a|b.ts",
      line: 4,
    },
  ];
  const engines: EngineResult[] = [
    { engine: "semgrep", findings, status: "failed", note: "parse\nfailed | hard" },
    { engine: "detekt", findings: [], status: "skipped", note: "no Kotlin" },
  ];
  const counts = countBySeverity(findings);
  const gate = evaluateGate(findings, { maxCritical: 0, maxHigh: 0, maxMedium: 50 });

  const summary = renderSummary(findings, counts, gate, true, engines);
  assert.match(summary, /semgrep.*failed/);
  assert.match(summary, /detekt.*skipped/);
  assert.match(summary, /rule\\\|id/);
  assert.match(summary, /src\/a\\\|b\.ts/);
  assert.doesNotMatch(summary, /parse\nfailed/);
});
