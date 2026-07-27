// SpotBugs + FindSecBugs engine adapter for Java/Kotlin.
// Compiles .java sources, downloads SpotBugs+FindSecBugs on demand, parses XML.
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";

const SPOTBUGS_VERSION = "4.8.6";
const SPOTBUGS_URL = `https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz`;
const SPOTBUGS_SHA256 = "b9d4d25e53cd4202b2dc19c549c0ff54f8a72fc76a71a8c40dee94422c67ebea";
const FINDSECBUGS_VERSION = "1.13.0";
const FINDSECBUGS_URL = `https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar`;
const FINDSECBUGS_SHA256 = "c239763a8c327b5fb653a34dece6398578bf435b9a32c212bb8e1abe701368a5";
const KOTLIN_VERSION = "1.9.24";
const KOTLIN_SHA256 = "eb7b68e01029fa67bc8d060ee54c12018f2c60ddc438cf21db14517229aa693b";

// FindSecBugs bug patterns considered high severity (security-critical).
const HIGH_PATTERNS = new Set([
  "SQL_INJECTION_JDBC",
  "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE",
  "COMMAND_INJECTION",
  "PATH_TRAVERSAL_IN",
  "XXE_SAXPARSER",
  "LDAP_INJECTION",
  "XPATH_INJECTION",
]);

function mapSeverity(type: string, priority: string): Severity {
  if (HIGH_PATTERNS.has(type)) return "high";
  const p = Number.parseInt(priority, 10);
  if (p === 1) return "high";
  if (p === 2) return "medium";
  return "low";
}

function findSourceFiles(dir: string, ext: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "target" || entry.name === "build") continue;
        walk(full);
      } else if (entry.name.endsWith(ext)) {
        out.push(full);
      }
    }
  };
  walk(dir);
  return out;
}

function findJavaFiles(dir: string): string[] {
  return findSourceFiles(dir, ".java");
}

function findKotlinFiles(dir: string): string[] {
  return findSourceFiles(dir, ".kt");
}

function findClassDirs(dir: string): string[] {
  // Look for typical compiled-output directories.
  const candidates = [
    "target/classes", // Maven
    "build/classes/kotlin/main", // Gradle Kotlin
    "build/classes/java/main", // Gradle Java
    "out/production/classes", // IntelliJ
  ];
  const found: string[] = [];
  for (const c of candidates) {
    const p = path.join(dir, c);
    if (fs.existsSync(p) && fs.readdirSync(p).length > 0) found.push(p);
  }
  return found;
}

async function tryProjectBuild(
  abs: string,
  noteParts: string[],
): Promise<string[]> {
  const mavenClasses = await tryMavenBuild(abs, noteParts);
  if (mavenClasses.length > 0) return mavenClasses;
  return tryGradleBuild(abs, noteParts);
}

async function tryMavenBuild(abs: string, noteParts: string[]): Promise<string[]> {
  if (!fs.existsSync(path.join(abs, "pom.xml")) || !(await which("mvn"))) return [];
  core.info("Detected pom.xml — running 'mvn compile' for a full classpath…");
  const result = await run("mvn", ["-q", "-B", "-DskipTests", "compile"], { cwd: abs });
  if (result.exitCode !== 0) noteParts.push("mvn compile had errors");
  return findClassDirs(abs);
}

async function gradleCommand(abs: string): Promise<string> {
  const gradlew = path.join(abs, "gradlew");
  if (fs.existsSync(gradlew)) return gradlew;
  return (await which("gradle")) ? "gradle" : "";
}

async function tryGradleBuild(abs: string, noteParts: string[]): Promise<string[]> {
  const hasGradle =
    fs.existsSync(path.join(abs, "build.gradle")) ||
    fs.existsSync(path.join(abs, "build.gradle.kts"));
  if (!hasGradle) return [];

  const command = await gradleCommand(abs);
  if (!command) return [];

  core.info("Detected Gradle build — running 'classes' task for a full classpath…");
  const result = await run(command, ["classes", "--console=plain", "-q"], { cwd: abs });
  if (result.exitCode !== 0) noteParts.push("gradle build had errors");
  return findClassDirs(abs);
}

async function ensureKotlinc(): Promise<string | null> {
  if (await which("kotlinc")) return "kotlinc";
  try {
    return await cachedTool(
      "kotlin-compiler",
      KOTLIN_VERSION,
      path.join("kotlinc", "bin", "kotlinc"),
      async (directory) => {
        const archive = await downloadVerified(
          `https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip`,
          KOTLIN_SHA256,
        );
        await tc.extractZip(archive, directory);
      },
    );
  } catch (err) {
    core.warning(`kotlinc download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

async function ensureSpotbugs(): Promise<string | null> {
  const cacheVersion = `${SPOTBUGS_VERSION}-findsecbugs-${FINDSECBUGS_VERSION}`;
  const executable = path.join(`spotbugs-${SPOTBUGS_VERSION}`, "bin", "spotbugs");
  try {
    return await cachedTool("spotbugs", cacheVersion, executable, async (directory) => {
      const archive = await downloadVerified(SPOTBUGS_URL, SPOTBUGS_SHA256);
      await tc.extractTar(archive, directory);

      const plugin = await downloadVerified(FINDSECBUGS_URL, FINDSECBUGS_SHA256);
      const pluginDir = path.join(directory, `spotbugs-${SPOTBUGS_VERSION}`, "plugin");
      fs.copyFileSync(plugin, path.join(pluginDir, "findsecbugs-plugin.jar"));
      fs.chmodSync(path.join(directory, executable), 0o700);
    });
  } catch (err) {
    core.warning(`spotbugs installation failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

async function compileJava(javaFiles: string[], classesDir: string, notes: string[]): Promise<void> {
  if (javaFiles.length === 0) return;
  const result = await run("javac", ["-d", classesDir, ...javaFiles]);
  if (result.exitCode !== 0) notes.push("javac had errors (missing deps?)");
}

async function compileKotlin(
  kotlinFiles: string[],
  classesDir: string,
  notes: string[],
): Promise<void> {
  if (kotlinFiles.length === 0) return;
  const command = await ensureKotlinc();
  if (!command) {
    notes.push("kotlinc unavailable");
    return;
  }
  const result = await run(command, [...kotlinFiles, "-d", classesDir]);
  if (result.exitCode !== 0) notes.push("kotlinc had errors (missing deps?)");
}

async function compileWithoutBuild(
  javaFiles: string[],
  kotlinFiles: string[],
  workdir: string,
  notes: string[],
): Promise<string[]> {
  if (!(await which("javac"))) {
    notes.push("javac not available");
    return [];
  }

  core.info("No build output found — falling back to direct javac/kotlinc compilation…");
  const classesDir = path.join(workdir, "classes");
  fs.mkdirSync(classesDir, { recursive: true });
  await compileJava(javaFiles, classesDir, notes);
  await compileKotlin(kotlinFiles, classesDir, notes);

  const hasClasses = fs.existsSync(classesDir) && fs.readdirSync(classesDir).length > 0;
  return hasClasses ? [classesDir] : [];
}

async function analyzeClasses(
  script: string,
  classDirs: string[],
  workdir: string,
  sources: string[],
): Promise<EngineResult> {
  const output = path.join(workdir, "spotbugs.xml");
  const result = await run(script, [
    "-textui",
    "-xml:withMessages",
    "-effort:max",
    "-low",
    "-output",
    output,
    ...classDirs,
  ]);
  if (!fs.existsSync(output)) {
    return {
      engine: "spotbugs",
      findings: [],
      status: "failed",
      note: `spotbugs run failed: ${result.stderr.slice(0, 200)}`,
    };
  }
  return {
    engine: "spotbugs",
    findings: parseSpotbugsXml(fs.readFileSync(output, "utf-8"), sources),
    status: "success",
  };
}

export async function runSpotbugs(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const javaFiles = findJavaFiles(abs);
  const kotlinFiles = findKotlinFiles(abs);
  const allSources = [...javaFiles, ...kotlinFiles];
  if (allSources.length === 0) {
    return { engine: "spotbugs", findings: [], status: "skipped", note: "no .java/.kt files found" };
  }

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-spotbugs-"));
  try {
    const noteParts: string[] = [];
    let classDirs = await tryProjectBuild(abs, noteParts);
    if (classDirs.length === 0) {
      classDirs = await compileWithoutBuild(javaFiles, kotlinFiles, workdir, noteParts);
    }

    if (classDirs.length === 0) {
      return {
        engine: "spotbugs",
        findings: [],
        status: "failed",
        note: `no .class files to analyze${noteParts.length ? " (" + noteParts.join("; ") + ")" : ""}`,
      };
    }

    const script = await ensureSpotbugs();
    if (!script) {
      return {
        engine: "spotbugs",
        findings: [],
        status: "failed",
        note: "spotbugs or FindSecBugs installation failed",
      };
    }

    const result = await analyzeClasses(script, classDirs, workdir, allSources);
    const notes = [...(result.note ? [result.note] : []), ...noteParts];
    result.note = notes.length > 0 ? notes.join("; ") : undefined;
    return result;
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}

// Lightweight XML parse (avoids a heavy XML dependency in the bundle).
export function parseSpotbugsXml(xml: string, javaFiles: string[]): Finding[] {
  const findings: Finding[] = [];
  const bugRe = /<BugInstance\b([^>]*)>([\s\S]*?)<\/BugInstance>/g;
  let m: RegExpExecArray | null;
  while ((m = bugRe.exec(xml)) !== null) {
    const attrs = m[1];
    const body = m[2];
    const type = /type="([^"]+)"/.exec(attrs)?.[1] ?? "SPOTBUGS";
    const priority = /priority="([^"]+)"/.exec(attrs)?.[1] ?? "2";
    const cweMatch = /cweid="([^"]+)"/.exec(attrs)?.[1];
    const sourceLine = /<SourceLine\b([^>]*)>/.exec(body)?.[1] ?? "";
    const sourcePath = /sourcepath="([^"]+)"/.exec(sourceLine)?.[1] ?? "";
    const start = /start="([^"]+)"/.exec(sourceLine)?.[1] ?? "0";
    const shortMsg = /<ShortMessage>([\s\S]*?)<\/ShortMessage>/.exec(body)?.[1]?.trim();
    // Resolve file path against the discovered java files when possible.
    const resolved =
      javaFiles.find((f) => f.endsWith(sourcePath)) ||
      javaFiles.find((f) => path.basename(f) === path.basename(sourcePath)) ||
      sourcePath ||
      "unknown";
    findings.push({
      engine: "spotbugs",
      ruleId: type,
      severity: mapSeverity(type, priority),
      message: shortMsg || type,
      file: resolved,
      line: Number.parseInt(start, 10) || 0,
      cwe: cweMatch ? `CWE-${cweMatch}` : undefined,
    });
  }
  return findings;
}
