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
  "gosec",
  "hadolint",
  "kotlin",
  "opengrep",
  "semgrep",
  "spotbugs",
  "trivy",
  "trufflehog",
  "zizmor",
];

test("tool lock contains every scanner dependency", () => {
  assert.equal(TOOL_LOCK_SCHEMA_VERSION, 1);
  assert.deepEqual(Object.keys(TOOLS).sort(), EXPECTED_TOOLS);
  for (const tool of Object.values(TOOLS)) {
    assert.match(tool.version, /^\d+(?:\.\d+)+$/);
  }
});

test("downloaded binary tools have pinned SHA-256 digests", () => {
  for (const name of [
    "detekt",
    "findsecbugs",
    "gitleaks",
    "gosec",
    "hadolint",
    "kotlin",
    "opengrep",
    "spotbugs",
    "trivy",
    "trufflehog",
    "zizmor",
  ] as const) {
    assert.match(TOOLS[name].sha256, /^[a-f0-9]{64}$/);
  }
});

test("tool metadata expands to the existing download URLs", () => {
  assert.equal(
    githubReleaseUrl(TOOLS.opengrep),
    "https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_manylinux_x86",
  );
  assert.equal(
    githubReleaseUrl(TOOLS.trivy),
    "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz",
  );
  assert.equal(
    githubReleaseUrl(TOOLS.spotbugs),
    "https://github.com/spotbugs/spotbugs/releases/download/4.9.8/spotbugs-4.9.8.tgz",
  );
  assert.equal(
    githubReleaseUrl(TOOLS.gosec),
    "https://github.com/securego/gosec/releases/download/v2.28.0/gosec_2.28.0_linux_amd64.tar.gz",
  );
  assert.equal(
    githubReleaseUrl(TOOLS.hadolint),
    "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-linux-x86_64",
  );
  assert.equal(
    mavenArtifactUrl(TOOLS.findsecbugs),
    "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.13.0/findsecbugs-plugin-1.13.0.jar",
  );
  assert.equal(
    githubReleaseUrl(TOOLS.zizmor),
    "https://github.com/zizmorcore/zizmor/releases/download/v1.29.0/zizmor-x86_64-unknown-linux-gnu.tar.gz",
  );
  assert.equal(
    githubReleaseUrl(TOOLS.trufflehog),
    "https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.0/trufflehog_3.97.0_linux_amd64.tar.gz",
  );
});
