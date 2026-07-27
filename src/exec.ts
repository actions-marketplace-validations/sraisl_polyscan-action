// Shared helper to run an external command and capture stdout/stderr,
// tolerating non-zero exit codes (linters exit non-zero when they find issues).
import * as exec from "@actions/exec";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export async function run(
  command: string,
  args: string[],
  options: { cwd?: string; env?: { [key: string]: string } } = {},
): Promise<RunResult> {
  let stdout = "";
  let stderr = "";
  let exitCode = 0;
  const mergedEnv: { [key: string]: string } = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) mergedEnv[k] = v;
  }
  if (options.env) Object.assign(mergedEnv, options.env);
  try {
    exitCode = await exec.exec(command, args, {
      cwd: options.cwd,
      env: mergedEnv,
      ignoreReturnCode: true,
      silent: true,
      listeners: {
        stdout: (data: Buffer) => {
          stdout += data.toString();
        },
        stderr: (data: Buffer) => {
          stderr += data.toString();
        },
      },
    });
  } catch (err) {
    return { exitCode: 127, stdout, stderr: String(err) };
  }
  return { exitCode, stdout, stderr };
}

// Check whether a binary is available on PATH.
export async function which(tool: string): Promise<boolean> {
  const res = await run("bash", ["-lc", `command -v ${tool} >/dev/null 2>&1`]);
  return res.exitCode === 0;
}

export interface PreparedTool {
  executable: string;
  cleanup: () => void;
}

// Python virtual environments contain absolute shebangs and cannot be moved
// into the tool cache. Keep the isolated environment alive for exactly one scan.
export async function ensurePythonTool(
  tool: string,
  version: string,
  label: string,
  core: { info: (s: string) => void; warning: (s: string) => void },
): Promise<PreparedTool | null> {
  if (await which(tool)) return { executable: tool, cleanup: () => undefined };

  core.info(`${label} not found — installing ${tool}==${version} in an isolated environment…`);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `polyscan-${tool}-`));
  try {
    const venv = path.join(directory, "venv");
    const create = await run("python3", ["-m", "venv", venv]);
    if (create.exitCode !== 0) throw new Error(create.stderr || "could not create Python venv");
    const install = await run(path.join(venv, "bin", "pip"), [
      "install",
      "--quiet",
      `${tool}==${version}`,
    ]);
    if (install.exitCode !== 0) throw new Error(install.stderr || "pip install failed");
    const executable = path.join(venv, "bin", tool);
    if (!fs.existsSync(executable)) throw new Error(`${tool} executable missing after install`);
    return {
      executable,
      cleanup: () => fs.rmSync(directory, { recursive: true, force: true }),
    };
  } catch (err) {
    fs.rmSync(directory, { recursive: true, force: true });
    core.warning(`${label} install failed: ${String(err).slice(0, 300)}`);
    return null;
  }
}
