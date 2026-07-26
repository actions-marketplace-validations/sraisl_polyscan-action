import * as path from "path";

// Resolve action inputs relative to the checked-out repository when GitHub
// provides it, instead of relying on the action process' current directory.
export function resolveTarget(target: string): string {
  if (path.isAbsolute(target)) return path.resolve(target);

  const workspace = process.env.GITHUB_WORKSPACE;
  if (workspace) return path.resolve(workspace, target);

  return path.resolve(target);
}
