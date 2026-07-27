import test from "node:test";
import assert from "node:assert/strict";

import {
  githubReleaseUrl,
  mavenArtifactUrl,
  TOOL_LOCK_SCHEMA_VERSION,
  TOOLS,
} from "../src/tool-versions";

const EXPECTED_TOOLS = [
  "bandit",
  "detekt",
  "eslint",
  "findsecbugs",
  "gitleaks",
  "kotlin",
  "semgrep",
  "spotbugs",
  "trivy",
];

test("tool lock contains every scanner dependency", () => {
  assert.equal(TOOL_LOCK_SCHEMA_VERSION, 1);
  assert.deepEqual(Object.keys(TOOLS).sort(), EXPECTED_TOOLS);
  for (const tool of Object.values(TOOLS)) {
    assert.match(tool.version, /^\d+(?:\.\d+)+$/);
  }
});

test("downloaded binary tools have pinned SHA-256 digests", () => {
  for (const name of ["detekt", "findsecbugs", "gitleaks", "kotlin", "spotbugs", "trivy"] as const) {
    assert.match(TOOLS[name].sha256, /^[a-f0-9]{64}$/);
  }
});

test("tool metadata expands to the existing download URLs", () => {
  assert.equal(
    githubReleaseUrl(TOOLS.trivy),
    "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz",
  );
  assert.equal(
    githubReleaseUrl(TOOLS.spotbugs),
    "https://github.com/spotbugs/spotbugs/releases/download/4.8.6/spotbugs-4.8.6.tgz",
  );
  assert.equal(
    mavenArtifactUrl(TOOLS.findsecbugs),
    "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.13.0/findsecbugs-plugin-1.13.0.jar",
  );
});
