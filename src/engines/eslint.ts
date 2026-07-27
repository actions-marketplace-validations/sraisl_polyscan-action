// ESLint engine adapter for JS/TS security-relevant rules.
// Uses a minimal flat config with no-eval / no-implied-eval and scans *.js/*.ts.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Finding, EngineResult, Severity } from "../schema";
import { run } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool } from "../tools";
import { TOOLS } from "../tool-versions";

const ESLINT_VERSION = TOOLS.eslint.version;

function mapSeverity(sev: number): Severity {
  // ESLint: 2 = error, 1 = warning
  return sev === 2 ? "high" : "medium";
}

const FLAT_CONFIG = `
module.exports = [
  {
    files: ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error"
    }
  }
];
`;

export function parseEslintJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  const data = JSON.parse(stdout);
  for (const file of data) {
    for (const m of file.messages ?? []) {
      if (!m.ruleId) continue; // parse errors etc.
      findings.push({
        engine: "eslint",
        ruleId: m.ruleId,
        severity: mapSeverity(m.severity),
        message: m.message,
        file: file.filePath,
        line: m.line ?? 0,
        column: m.column,
      });
    }
  }
  return findings;
}

export async function runEslint(target: string): Promise<EngineResult> {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-eslint-"));
  try {
    let eslintBin: string;
    try {
      eslintBin = await cachedTool(
        "polyscan-eslint",
        ESLINT_VERSION,
        path.join("node_modules", ".bin", "eslint"),
        async (directory) => {
          const install = await run(
            "npm",
            ["install", "--no-audit", "--no-fund", "--silent", `eslint@${ESLINT_VERSION}`],
            { cwd: directory },
          );
          if (install.exitCode !== 0) throw new Error(install.stderr || "npm install failed");
        },
      );
    } catch (err) {
      return {
        engine: "eslint",
        findings: [],
        status: "failed",
        note: `eslint install failed: ${String(err).slice(0, 200)}`,
      };
    }

    const configPath = path.join(workdir, "eslint.config.cjs");
    fs.writeFileSync(configPath, FLAT_CONFIG);

    const absTarget = resolveTarget(target);
    const res = await run(
      eslintBin,
      ["--config", configPath, "--no-ignore", "-f", "json", "."],
      { cwd: absTarget, env: { ESLINT_USE_FLAT_CONFIG: "true" } },
    );
    if (res.exitCode > 1) {
      return {
        engine: "eslint",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 200) || `eslint exited ${res.exitCode}`,
      };
    }

    if (!res.stdout.trim()) {
      return {
        engine: "eslint",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 200) || "eslint produced no output",
      };
    }

    let findings: Finding[];
    try {
      findings = parseEslintJson(res.stdout);
    } catch (err) {
      return {
        engine: "eslint",
        findings: [],
        status: "failed",
        note: `parse error: ${String(err).slice(0, 200)}`,
      };
    }

    return { engine: "eslint", findings, status: "success" };
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}
