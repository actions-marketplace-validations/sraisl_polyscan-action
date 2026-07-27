// Trivy engine adapter — filesystem scan for vulnerable dependencies and
// misconfigurations (SCA + IaC), with optional container image scan.
// Installs the trivy binary on demand.
import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";

const TRIVY_VERSION = "0.72.0";
const TRIVY_SHA256 = "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea";

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

async function ensureTrivy(): Promise<string | null> {
  if (await which("trivy")) return "trivy";
  core.info(`trivy not found — downloading v${TRIVY_VERSION}…`);
  try {
    return await cachedTool("trivy", TRIVY_VERSION, "trivy", async (directory) => {
      const archive = await downloadVerified(
        `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`,
        TRIVY_SHA256,
      );
      await tc.extractTar(archive, directory);
      fs.chmodSync(path.join(directory, "trivy"), 0o755);
    });
  } catch (err) {
    core.warning(`trivy download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export function parseTrivyData(data: unknown, imageRef?: string): Finding[] {
  const findings: Finding[] = [];
  for (const result of (data as { Results?: unknown[] }).Results ?? []) {
    const r = result as {
      Target?: string;
      Vulnerabilities?: unknown[];
      Misconfigurations?: unknown[];
    };
    const artifact = r.Target ?? "unknown";
    for (const v of r.Vulnerabilities ?? []) {
      const vuln = v as {
        VulnerabilityID?: string;
        PkgName?: string;
        InstalledVersion?: string;
        FixedVersion?: string;
        Severity?: string;
        Title?: string;
        CweIDs?: string[];
      };
      const fixed = vuln.FixedVersion ? ` (fixed in ${vuln.FixedVersion})` : "";
      findings.push({
        engine: "trivy",
        ruleId: vuln.VulnerabilityID ?? "TRIVY-VULN",
        severity: mapSeverity(vuln.Severity ?? ""),
        message: `${vuln.PkgName}@${vuln.InstalledVersion}: ${vuln.Title ?? vuln.VulnerabilityID}${fixed}`,
        file: artifact,
        line: 0,
        cwe: Array.isArray(vuln.CweIDs) && vuln.CweIDs.length ? vuln.CweIDs[0] : undefined,
        source: imageRef ? `image:${imageRef}` : undefined,
      });
    }
    for (const mc of r.Misconfigurations ?? []) {
      const m = mc as {
        ID?: string;
        Title?: string;
        Message?: string;
        Severity?: string;
        CauseMetadata?: { StartLine?: number };
      };
      findings.push({
        engine: "trivy",
        ruleId: m.ID ?? "TRIVY-MISCONF",
        severity: mapSeverity(m.Severity ?? ""),
        message: `${m.Title ?? m.ID}: ${m.Message ?? ""}`.trim(),
        file: artifact,
        line: m.CauseMetadata?.StartLine ?? 0,
        source: imageRef ? `image:${imageRef}` : undefined,
      });
    }
  }
  return findings;
}

export async function runTrivy(target: string, image?: string): Promise<EngineResult> {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-trivy-"));
  try {
    const bin = await ensureTrivy();
    if (!bin) {
      return { engine: "trivy", findings: [], status: "failed", note: "trivy not installed" };
    }

    const allFindings: Finding[] = [];
    const notes: string[] = [];

    // --offline-scan avoids resolving parent POMs over the network.
    const fsOut = path.join(workdir, "trivy-fs.json");
    const fsRes = await run(bin, [
      "fs",
      "--scanners",
      "vuln,misconfig",
      "--offline-scan",
      "--format",
      "json",
      "--output",
      fsOut,
      "--quiet",
      resolveTarget(target),
    ]);
    if (fsRes.exitCode !== 0) {
      notes.push(`fs scan exited ${fsRes.exitCode}: ${fsRes.stderr.slice(0, 120)}`);
    }
    if (fs.existsSync(fsOut)) {
      try {
        allFindings.push(...parseTrivyData(JSON.parse(fs.readFileSync(fsOut, "utf-8"))));
      } catch (err) {
        notes.push(`fs parse error: ${String(err).slice(0, 150)}`);
      }
    } else {
      notes.push(`fs scan produced no output: ${fsRes.stdout.slice(0, 150)}`);
    }

    if (image) {
      core.info(`trivy: scanning image "${image}"…`);
      const imgOut = path.join(workdir, "trivy-image.json");
      const imgRes = await run(bin, [
        "image",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        imgOut,
        "--quiet",
        image,
      ]);
      if (imgRes.exitCode !== 0) {
        notes.push(`image scan exited ${imgRes.exitCode}: ${imgRes.stderr.slice(0, 120)}`);
      }
      if (fs.existsSync(imgOut)) {
        try {
          allFindings.push(
            ...parseTrivyData(JSON.parse(fs.readFileSync(imgOut, "utf-8")), image),
          );
        } catch (err) {
          notes.push(`image parse error: ${String(err).slice(0, 150)}`);
        }
      } else {
        notes.push(`image scan produced no output: ${imgRes.stdout.slice(0, 150)}`);
      }
    }

    return {
      engine: "trivy",
      findings: allFindings,
      status: notes.length ? "failed" : "success",
      note: notes.length ? notes.join("; ") : undefined,
    };
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}
