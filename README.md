# PolyScan Action

**Multi-language SAST as a native GitHub Action.** One step runs all configured security engines — Semgrep, Bandit, ESLint, SpotBugs, detekt, Trivy and gitleaks — normalizes every result into a single schema, enforces a configurable **Quality Gate**, and emits **SARIF**, a **CycloneDX SBOM** and a rich **job summary** — plus optional artifact upload.

Written in TypeScript, bundled with `@vercel/ncc`, runs as a native GitHub Action on the `node24` runtime. PolyScan supports Linux x64 runners.

## Usage

```yaml
name: PolyScan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # only needed for upload-sarif

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: sraisl/polyscan-action@v6
        with:
          target: "."
          engines: "semgrep,bandit,eslint,spotbugs"
          max-critical: "0"
          max-high: "0"
          max-medium: "50"
          gate: "true"
          fail-on-engine-error: "true"
          sarif: "true"
          sbom: "true"
          upload-artifacts: "true"

      # optional: push SARIF into GitHub Code Scanning
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: polyscan.sarif
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `target` | `.` | Workspace-contained directory to scan |
| `engines` | `all` | `all` or comma-separated engines: `semgrep,bandit,eslint,spotbugs,trivy,detekt,gitleaks` |
| `max-concurrency` | `2` | Maximum concurrent read-only engines (`1`-`7`); SpotBugs runs as a serial barrier |
| `max-critical` | `0` | Max critical findings before the gate fails |
| `max-high` | `0` | Max high findings before the gate fails |
| `max-medium` | `50` | Max medium findings before the gate fails |
| `gate` | `true` | Enforce the Quality Gate (fail the job) |
| `fail-on-engine-error` | `true` | Fail after reports are written if a requested engine cannot complete |
| `sarif` | `true` | Write `polyscan.sarif` (SARIF 2.1.0) |
| `sbom` | `false` | Write `polyscan.sbom.json` (CycloneDX 1.5) |
| `upload-artifacts` | `true` | Upload SARIF + SBOM + summary as a workflow artifact |
| `upload-sarif` | `false` | Emit a hint to upload SARIF to code scanning (use the CodeQL step) |
| `trivy-image` | _(empty)_ | Docker image to scan with `trivy image` (e.g. `myapp:latest`). Image must be available in the local Docker daemon. Runs in addition to the filesystem scan. |
| `output-dir` | `.` | Workspace-contained directory for generated reports |

## Outputs

| Output | Description |
|---|---|
| `total` | Total findings |
| `critical` / `high` / `medium` / `low` / `info` | Counts per severity |
| `gate-passed` | `'true'` / `'false'` |
| `engines-passed` | `'true'` when every requested engine completed or was not applicable |
| `failed-engines` | Comma-separated engines that failed |
| `sarif-file` | Path to the SARIF file |
| `sbom-file` | Path to the SBOM file |

## Engines

| Engine | Languages | Notes |
|---|---|---|
| **Semgrep** | many | `--config auto` |
| **Bandit** | Python | installed via pip on demand |
| **ESLint** | JS/TS | `no-eval` / `no-implied-eval` / `no-new-func` |
| **SpotBugs + FindSecBugs** | Java + Kotlin | **build-aware**: runs `mvn compile` / `gradle classes` when a build file is present (full dependency classpath), else falls back to direct `javac`/`kotlinc` |
| **Trivy** | deps + IaC | SCA (vulnerable dependencies / CVEs) + misconfig; binary downloaded on demand |
| **detekt** | Kotlin | Kotlin-native static analysis (incl. security rules) via detekt CLI; SARIF parsed |
| **gitleaks** | git history + working tree | Secret / credential detection (API keys, tokens, passwords) via gitleaks CLI; SARIF parsed |

Python engines are installed into isolated, version-pinned environments; downloaded tools are cached and verified with SHA-256. SpotBugs is **build-aware** — for real Java/Kotlin projects it invokes the project's own build (Maven/Gradle) so the full dependency classpath is available, which is required to detect data-flow bugs (SQLi, command injection) on **Java** (FindSecBugs does not target Kotlin bytecode). For **Kotlin** code-security use **detekt**, which analyzes Kotlin source natively. Trivy runs `--offline-scan` to avoid Maven Central rate limits.

**Default: all engines run** (`engines: "all"` expands to `semgrep,bandit,eslint,spotbugs,trivy,detekt,gitleaks`). Restrict via the `engines` input, e.g. `engines: "spotbugs,trivy,detekt"`.

Read-only engines run with bounded concurrency (`max-concurrency`, default `2`). SpotBugs may invoke a project build and therefore runs as a serial barrier: all earlier engines finish before it starts, and later engines start only after it completes.

## Updating scanner tools

Scanner and helper-tool versions are pinned centrally in `tools.lock.json`.

```bash
npm run engines:list
npm run engines:check
npm run engines:check -- trivy semgrep
npm run engines:update -- trivy 0.73.0
```

`engines:check` only reads official provider metadata. `engines:update` requires an explicit version, validates it against GitHub Releases, PyPI, npm, or Maven Central, verifies downloaded binary artifacts against provider checksums, updates the lock file, then runs the typecheck, tests, and production bundle build. Use `--dry-run` to verify an update without writing files. `--skip-project-checks` skips only the local typecheck, tests, and build; provider and artifact verification always remain enabled.

## Development

```bash
nvm use
npm install
npm run typecheck
npm run build      # bundles src/main.ts -> dist/index.js (must be committed)
```

> The `dist/` folder is committed on purpose — GitHub runs the bundled `dist/index.js` directly.

## License

MIT © Stefan Raisl
