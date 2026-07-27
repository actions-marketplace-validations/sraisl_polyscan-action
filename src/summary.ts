// Render a Markdown job summary for GitHub Actions.
import { Finding, SeverityCounts } from "./schema";
import { GateResult } from "./gate";
import { EngineResult } from "./schema";

const SEV_EMOJI: Record<string, string> = {
  critical: "🟣",
  high: "🔴",
  medium: "🟠",
  low: "🟡",
  info: "⚪",
};

function tableCell(value: string): string {
  return value.replace(/\r?\n/g, " ").replace(/\|/g, "\\|").trim();
}

function code(value: string): string {
  return `\`${tableCell(value).replace(/`/g, "'")}\``;
}

export function renderSummary(
  findings: Finding[],
  counts: SeverityCounts,
  gate: GateResult,
  gateEnforced: boolean,
  engineResults: EngineResult[],
): string {
  const lines: string[] = [];
  lines.push("## 🔍 PolyScan Report");
  lines.push("");

  // Severity table
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  lines.push(`| ${SEV_EMOJI.critical} Critical | ${counts.critical} |`);
  lines.push(`| ${SEV_EMOJI.high} High | ${counts.high} |`);
  lines.push(`| ${SEV_EMOJI.medium} Medium | ${counts.medium} |`);
  lines.push(`| ${SEV_EMOJI.low} Low | ${counts.low} |`);
  lines.push(`| ${SEV_EMOJI.info} Info | ${counts.info} |`);
  lines.push(`| **Total** | **${counts.total}** |`);
  lines.push("");

  // Engine status
  lines.push("### Engines");
  for (const e of engineResults) {
    const icon = e.status === "success" ? "✅" : e.status === "skipped" ? "ℹ️" : "⚠️";
    const note = e.note ? ` — _${tableCell(e.note)}_` : "";
    lines.push(`- ${icon} **${tableCell(e.engine)}**: ${e.findings.length} findings (${e.status})${note}`);
  }
  lines.push("");

  // Secret / leak findings (gitleaks) — shown prominently regardless of the
  // top-50 cap on the generic findings table, since secrets deserve visibility.
  const secrets = findings.filter((f) => f.engine === "gitleaks");
  if (secrets.length > 0) {
    lines.push("### 🔑 Secrets Detected (gitleaks)");
    lines.push("");
    lines.push("| Rule | Location | Severity |");
    lines.push("|---|---|---|");
    for (const f of secrets) {
      const cleanFile = f.file.replace(/^\.\//, "");
      const loc = f.line > 0 ? `${cleanFile}:${f.line}` : cleanFile;
      lines.push(`| ${code(f.ruleId)} | ${code(loc)} | ${SEV_EMOJI[f.severity]} ${f.severity} |`);
    }
    lines.push("");
    lines.push("_gitleaks is run with `--redact`: secret values are masked by gitleaks at source and do not appear in logs or SARIF._");
    lines.push("");
  }

  // Container image findings (trivy image scan) — shown in a dedicated block.
  const imageFindings = findings.filter((f) => f.source?.startsWith("image:"));
  if (imageFindings.length > 0) {
    const imageName = imageFindings[0].source!.slice("image:".length);
    lines.push(`### 🐳 Container Image Scan (${code(imageName)})`);
    lines.push("");
    lines.push("| Sev | CVE / Rule | Finding | Layer |");
    lines.push("|---|---|---|---|");
    for (const f of imageFindings) {
      const cwe = f.cwe ? ` (${f.cwe})` : "";
      lines.push(`| ${SEV_EMOJI[f.severity]} ${f.severity} | ${code(f.ruleId)}${cwe} | ${tableCell(f.message)} | ${tableCell(f.file)} |`);
    }
    lines.push("");
  }

  // Findings table (top 50)
  if (findings.length > 0) {
    lines.push("### Findings");
    lines.push("| Sev | Rule | Location | Engine |");
    lines.push("|---|---|---|---|");
    const shown = findings.slice(0, 50);
    for (const f of shown) {
      const cleanFile = f.file.replace(/^\.\//, "");
      const loc = f.line > 0 ? `${cleanFile}:${f.line}` : cleanFile;
      const cwe = f.cwe ? ` (${f.cwe})` : "";
      lines.push(
        `| ${SEV_EMOJI[f.severity]} ${f.severity} | ${code(f.ruleId)}${cwe} | ${code(loc)} | ${tableCell(f.engine)} |`,
      );
    }
    if (findings.length > shown.length) {
      lines.push("");
      lines.push(`_… and ${findings.length - shown.length} more findings._`);
    }
    lines.push("");
  }

  // Quality Gate
  lines.push("### Quality Gate");
  if (!gateEnforced) {
    lines.push("> ℹ️ Quality Gate not enforced (`gate: false`).");
  } else if (gate.passed) {
    lines.push("> ✅ **Passed** — thresholds satisfied.");
  } else {
    lines.push(`> ❌ **Failed** — ${gate.reasons.join(", ")}.`);
  }
  lines.push("");

  return lines.join("\n");
}
