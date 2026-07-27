// Semgrep engine adapter — installs via pip if missing, runs with auto config.
import * as core from "@actions/core";
import { Finding, EngineResult, Severity } from "../schema";
import { run, ensurePythonTool } from "../exec";
import { resolveTarget } from "../target";
import { TOOLS } from "../tool-versions";

const SEMGREP_VERSION = TOOLS.semgrep.version;

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "low";
    default:
      return "medium";
  }
}

async function ensureInstalled() {
  return ensurePythonTool("semgrep", SEMGREP_VERSION, "semgrep", core);
}

export function parseSemgrepJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  const data = JSON.parse(stdout);
  for (const r of data.results ?? []) {
    const meta = r.extra?.metadata ?? {};
    const cweRaw = meta.cwe;
    const cwe = Array.isArray(cweRaw) ? cweRaw[0] : cweRaw;
    findings.push({
      engine: "semgrep",
      ruleId: String(r.check_id ?? "semgrep-rule").split(".").pop() || "semgrep-rule",
      severity: mapSeverity(r.extra?.severity),
      message: r.extra?.message?.trim() || "Semgrep finding",
      file: r.path,
      line: r.start?.line ?? 0,
      column: r.start?.col,
      cwe: cwe ? /CWE-\d+/.exec(String(cwe))?.[0] : undefined,
    });
  }
  return findings;
}

export async function runSemgrep(target: string): Promise<EngineResult> {
  const tool = await ensureInstalled();
  if (!tool) {
    return { engine: "semgrep", findings: [], status: "failed", note: "semgrep not installed" };
  }
  try {
    const abs = resolveTarget(target);

    const res = await run(tool.executable, [
      "--config",
      "auto",
      "--json",
      "--quiet",
      "--no-git-ignore",
      abs,
    ]);
    if (res.exitCode !== 0) {
      return {
        engine: "semgrep",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 300) || `semgrep exited ${res.exitCode}`,
      };
    }

    if (!res.stdout.trim()) {
      return {
        engine: "semgrep",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 300) || "semgrep produced no output",
      };
    }

    let findings: Finding[];
    try {
      findings = parseSemgrepJson(res.stdout);
    } catch (err) {
      return {
        engine: "semgrep",
        findings: [],
        status: "failed",
        note: `parse error: ${String(err).slice(0, 200)}`,
      };
    }

    return { engine: "semgrep", findings, status: "success" };
  } finally {
    tool.cleanup();
  }
}
