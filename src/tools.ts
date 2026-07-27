import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";

export function assertSupportedPlatform(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): void {
  if (platform !== "linux" || arch !== "x64") {
    throw new Error(
      `PolyScan supports Linux x64 runners; received ${platform} ${arch}`,
    );
  }
}

export function sha256File(file: string): string {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(file));
  return hash.digest("hex");
}

export function verifySha256(file: string, expectedSha256: string): void {
  const actual = sha256File(file);
  if (actual !== expectedSha256.toLowerCase()) {
    throw new Error(`checksum mismatch: expected ${expectedSha256}, got ${actual}`);
  }
}

export async function downloadVerified(url: string, expectedSha256: string): Promise<string> {
  const file = await tc.downloadTool(url);
  try {
    verifySha256(file, expectedSha256);
  } catch (err) {
    throw new Error(`${String(err)} for ${url}`);
  }
  return file;
}

export async function withTempDir<T>(
  prefix: string,
  run: (directory: string) => Promise<T>,
): Promise<T> {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    return await run(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

export async function cachedTool(
  name: string,
  version: string,
  executable: string,
  install: (directory: string) => Promise<void>,
): Promise<string> {
  const cached = tc.find(name, version, process.arch);
  if (cached) {
    const cachedExecutable = path.join(cached, executable);
    if (fs.existsSync(cachedExecutable)) return cachedExecutable;
    throw new Error(`${name} cache entry is incomplete: missing ${executable}`);
  }

  return withTempDir(`polyscan-${name}-`, async (directory) => {
    await install(directory);
    const source = path.join(directory, executable);
    if (!fs.existsSync(source)) throw new Error(`${name} installation did not produce ${executable}`);
    const cachedDirectory = await tc.cacheDir(directory, name, version, process.arch);
    return path.join(cachedDirectory, executable);
  });
}
