// Render a Markdown job summary for GitHub Actions.
import { EngineResult, Finding, SeverityCounts } from "./schema";
import { GateResult } from "./gate";

const SEV_EMOJI: Record<string, string> = {
  critical: "🟣",
  high: "🔴",
  medium: "🟠",
  low: "🟡",
  info: "⚪",
};

function tableCell(value: string): string {
  return value
    .replaceAll(/\r?\n/g, " ")
    .replaceAll("|", String.raw`\|`)
    .trim();
}

function code(value: string): string {
  return `\`${tableCell(value).replaceAll("`", "'")}\``;
}

function severitySection(counts: SeverityCounts): string[] {
  return [
    "| Severity | Count |",
    "|---|---|",
    `| ${SEV_EMOJI.critical} Critical | ${counts.critical} |`,
    `| ${SEV_EMOJI.high} High | ${counts.high} |`,
    `| ${SEV_EMOJI.medium} Medium | ${counts.medium} |`,
    `| ${SEV_EMOJI.low} Low | ${counts.low} |`,
    `| ${SEV_EMOJI.info} Info | ${counts.info} |`,
    `| **Total** | **${counts.total}** |`,
    "",
  ];
}

function engineIcon(result: EngineResult): string {
  if (result.status === "success") return "✅";
  if (result.status === "skipped") return "ℹ️";
  return "⚠️";
}

function engineSection(results: EngineResult[]): string[] {
  const lines = ["### Engines"];
  for (const result of results) {
    const note = result.note ? ` — _${tableCell(result.note)}_` : "";
    lines.push(
      `- ${engineIcon(result)} **${tableCell(result.engine)}**: ` +
        `${result.findings.length} findings (${result.status})${note}`,
    );
  }
  return [...lines, ""];
}

function findingLocation(finding: Finding): string {
  const cleanFile = finding.file.startsWith("./") ? finding.file.slice(2) : finding.file;
  return finding.line > 0 ? `${cleanFile}:${finding.line}` : cleanFile;
}

function secretsSection(findings: Finding[]): string[] {
  const secrets = findings.filter((finding) => finding.engine === "gitleaks");
  if (secrets.length === 0) return [];

  const lines = [
    "### 🔑 Secrets Detected (gitleaks)",
    "",
    "| Rule | Location | Severity |",
    "|---|---|---|",
  ];
  for (const finding of secrets) {
    lines.push(
      `| ${code(finding.ruleId)} | ${code(findingLocation(finding))} | ` +
        `${SEV_EMOJI[finding.severity]} ${finding.severity} |`,
    );
  }
  return [
    ...lines,
    "",
    "_gitleaks is run with `--redact`: secret values are masked by gitleaks at source and do not appear in logs or SARIF._",
    "",
  ];
}

function imageSection(findings: Finding[]): string[] {
  const imageFindings = findings.filter((finding) => finding.source?.startsWith("image:"));
  if (imageFindings.length === 0) return [];

  const imageName = imageFindings[0].source?.slice("image:".length) ?? "unknown";
  const lines = [
    `### 🐳 Container Image Scan (${code(imageName)})`,
    "",
    "| Sev | CVE / Rule | Finding | Layer |",
    "|---|---|---|---|",
  ];
  for (const finding of imageFindings) {
    const cwe = finding.cwe ? ` (${finding.cwe})` : "";
    lines.push(
      `| ${SEV_EMOJI[finding.severity]} ${finding.severity} | ` +
        `${code(finding.ruleId)}${cwe} | ${tableCell(finding.message)} | ` +
        `${tableCell(finding.file)} |`,
    );
  }
  return [...lines, ""];
}

function findingsSection(findings: Finding[]): string[] {
  if (findings.length === 0) return [];

  const shown = findings.slice(0, 50);
  const lines = [
    "### Findings",
    "| Sev | Rule | Location | Engine |",
    "|---|---|---|---|",
  ];
  for (const finding of shown) {
    const cwe = finding.cwe ? ` (${finding.cwe})` : "";
    lines.push(
      `| ${SEV_EMOJI[finding.severity]} ${finding.severity} | ` +
        `${code(finding.ruleId)}${cwe} | ${code(findingLocation(finding))} | ` +
        `${tableCell(finding.engine)} |`,
    );
  }
  if (findings.length > shown.length) {
    lines.push("", `_… and ${findings.length - shown.length} more findings._`);
  }
  return [...lines, ""];
}

function gateSection(gate: GateResult, enforced: boolean): string[] {
  let result: string;
  if (!enforced) {
    result = "> ℹ️ Quality Gate not enforced (`gate: false`).";
  } else if (gate.passed) {
    result = "> ✅ **Passed** — thresholds satisfied.";
  } else {
    result = `> ❌ **Failed** — ${gate.reasons.join(", ")}.`;
  }
  return ["### Quality Gate", result, ""];
}

export function renderSummary(
  findings: Finding[],
  counts: SeverityCounts,
  gate: GateResult,
  gateEnforced: boolean,
  engineResults: EngineResult[],
): string {
  return [
    "## 🔍 PolyScan Report",
    "",
    ...severitySection(counts),
    ...engineSection(engineResults),
    ...secretsSection(findings),
    ...imageSection(findings),
    ...findingsSection(findings),
    ...gateSection(gate, gateEnforced),
  ].join("\n");
}
