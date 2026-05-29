```text
 __  __  ____    _    ___ _____ _____ _____
|  \/  |/ ___|  / \  |_ _|  ___| ____| ____|
| |\/| | |     / _ \  | || |_  |  _| |  _|
| |  | | |___ / ___ \ | ||  _| | |___| |___
|_|  |_|\____/_/   \_\___|_|   |_____|_____|
          npm / pnpm / yarn / bun gate
```

Mcaifee is a Rust CLI and agent skill for gating npm, pnpm, Yarn, and Bun dependency changes before package lifecycle scripts can run.

It is meant for agent-driven development, CI gates, and local installs where a package manager command might add new JavaScript dependencies. Mcaifee checks package specs, manifests, lockfiles, registry metadata, and optional Docker behavior signals before handing control back to the package manager.

The repository includes a portable `SKILL.md` entrypoint for any agent runtime that can read skill-style instructions and run local commands. It is not tied to a single agent implementation.

## What It Does

- Wraps `npm`, `pnpm`, `yarn`, and `bun` commands such as `install`, `add`, `update`, and `ci`.
- Stages npm lockfile changes with scripts disabled before the real install path runs.
- Audits `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, and legacy `bun.lockb` signals.
- Flags lifecycle install scripts, suspicious script content, local specs, Git/SSH specs, HTTP tarballs, missing integrity hashes, broad version ranges, Node core-module shadowing, and likely typosquats.
- Uses `npm view` in `--online` mode to inspect registry metadata without running package code.
- Runs npm/pnpm advisory audit in `--online` mode for supported lockfiles and emits CVE/GHSA findings.
- Flags package versions that are newer than the configured minimum age, 7 days by default.
- Matches resolved packages against a local source database built from OSV-style malicious package records through `mcaifee db update`.
- Prints full text or JSON reports through `report` and `audit`.
- Writes redacted invocation logs with retention controls and inspection commands.
- Provides `mcaifee doctor` for local health checks of config, cache, logs, source DB, and required tools.
- Can run a Docker behavior simulation in paranoia mode with network disabled by default.

Mcaifee is a gate, not a complete malware oracle. A clean result means the configured checks did not flag risk; it does not prove a package is benign.

## Install

Install from the latest GitHub Release:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/mcaifee/main/install.sh | sh
```

Install a specific version, destination, or persistent shell integration:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/mcaifee/main/install.sh | sh -s -- --version v0.5.1
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/mcaifee/main/install.sh | sh -s -- --install-dir /usr/local/bin --shell-init zsh
```

Install for Codex agent sessions, including the skill and a PATH-visible symlink for headless runs:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/mcaifee/main/install.sh | sh -s -- --agent-skill --path-link
```

Or download a release binary manually:

```bash
curl -L -o mcaifee https://github.com/turinglabsorg/mcaifee/releases/latest/download/mcaifee-linux-x86_64
chmod +x mcaifee
sudo mv mcaifee /usr/local/bin/mcaifee
```

macOS assets are published as:

```text
mcaifee-macos-aarch64
mcaifee-macos-x86_64
```

Build from source:

```bash
cargo build --release --locked
./target/release/mcaifee --help
```

## Configuration

Mcaifee stores user policy in `~/.mcaifee/config.json` and cache data in `~/.mcaifee/cache/`.

Create or inspect the default config:

```bash
mcaifee config init
mcaifee config status
```

Default config:

```json
{
  "minimumVersionAgeHours": 168,
  "sourceDbMaxAgeHours": 24,
  "failOn": "medium",
  "autoUpdateSourceDb": true,
  "allowRegistryHosts": ["registry.npmjs.org"],
  "timeoutSeconds": 20,
  "logInvocations": true,
  "logDir": "~/.mcaifee/logs",
  "logRetentionDays": 30,
  "cacheDir": "~/.mcaifee/cache",
  "sourceDbPath": null
}
```

Policy precedence is command flag, environment variable, config file, then built-in default. The minimum package version age can be overridden per command:

```bash
mcaifee scan react@18.2.0 --online --min-version-age-hours 72
mcaifee npm install react --mcaifee-min-version-age-hours 72
```

Set `minimumVersionAgeHours` to `0`, or pass `--min-version-age-hours 0`, to disable the publish-age gate for that scope.

## Invocation Logs

Mcaifee records one JSONL event per invocation in `~/.mcaifee/logs/` by default. The log includes command mode, redacted arguments, current working directory, executable path, process ID, start and finish timestamps, duration, exit code, and success state.

Logs are best-effort: logging failures never block the dependency gate. Sensitive argument names such as tokens, passwords, credentials, auth values, API keys, and URL credentials are redacted before writing.

By default, invocation logs older than 30 days are pruned after successful log writes. Set `logRetentionDays` or `MCAIFEE_LOG_RETENTION_DAYS`; use `0` to disable automatic pruning.

Configuration:

```bash
MCAIFEE_LOG_INVOCATIONS=0 mcaifee npm install
MCAIFEE_LOG_DIR=/tmp/mcaifee-logs mcaifee report
MCAIFEE_LOG_RETENTION_DAYS=14 mcaifee report
```

Or set `logInvocations`, `logDir`, and `logRetentionDays` in `~/.mcaifee/config.json`.

Inspect or prune logs:

```bash
mcaifee logs status
mcaifee logs tail --lines 50
mcaifee logs prune --days 30 --dry-run
mcaifee logs prune --days 30
```

## Doctor

Use `doctor` to verify the local install without running package lifecycle code:

```bash
mcaifee doctor
mcaifee doctor --format json
mcaifee doctor --strict
```

The health check covers config parsing, the active executable, cache/log directory writability, source database freshness, and the presence of `npm`, `pnpm`, `yarn`, `bun`, and `docker` on `PATH`. Warnings do not fail by default; `--strict` exits non-zero when warnings are present.

## Wrapper Usage

Use Mcaifee where you would normally call a package manager:

```bash
mcaifee npm install
mcaifee npm install react
mcaifee npm ci
mcaifee pnpm add vite
mcaifee yarn add lodash
mcaifee bun add zod
```

If shell integration was installed, plain package-manager commands pass through Mcaifee automatically:

```bash
npm install
pnpm install --paranoia
yarn add vite
bun add zod
```

For one-off current-shell activation without editing shell startup files:

```bash
eval "$(mcaifee shell-init --shell zsh)"
```

Disable the current shell session:

```bash
eval "$(mcaifee shell-disable --shell zsh)"
```

Remove the persistent shell startup block:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/mcaifee/main/install.sh | sh -s -- --shell-disable zsh
```

Check whether the current shell has the Mcaifee environment marker:

```bash
mcaifee shell-status
```

By default the wrapper blocks when findings reach `medium` severity. Override this per command:

```bash
mcaifee npm install --mcaifee-fail-on high
mcaifee npm install --mcaifee-fail-on critical
mcaifee npm install --mcaifee-allow-registry-host registry.example.com
mcaifee npm install --mcaifee-timeout 45
```

Or with an environment variable:

```bash
MCAIFEE_FAIL_ON=high mcaifee npm install
```

Emergency bypass:

```bash
MCAIFEE_BYPASS=1 mcaifee npm install
```

Mcaifee's internal npm staging and metadata calls use an isolated temporary npm cache and log directory, so broken permissions in a user's `~/.npm` cache do not leak into the pre-install gate. The final package-manager command still runs with the user's normal npm configuration after the gate passes.

## Scanner Usage

Scan package specs:

```bash
mcaifee scan react@18.2.0 react-dom@18.2.0
```

Scan a manifest and lockfile:

```bash
mcaifee scan --package-json package.json --lockfile package-lock.json
```

Use registry metadata and package-manager advisory audit when network access is allowed:

```bash
mcaifee scan left-pad --online
mcaifee report --online
```

Fail with exit code `2` at or above a threshold:

```bash
mcaifee scan --lockfile package-lock.json --fail-on medium
```

## Source Database

`mcaifee db update` builds a local cache of machine-readable package intelligence. Without `--source`, it clones or updates OpenSSF `malicious-packages` and imports npm OSV records:

```bash
mcaifee db update
mcaifee db status
```

Import a local OSV-style source instead:

```bash
mcaifee db update --source ./malicious-packages/osv --db ./mcaifee-source-db.json
MCAIFEE_DB_PATH=./mcaifee-source-db.json mcaifee audit --format json
```

The scanner matches exact package versions from lockfiles against this database and emits `source_db_match` findings with source, advisory ID, confidence, and evidence URL.

Package-manager wrappers automatically refresh the default source database before gated installs when the database is missing or older than 24 hours. Set `MCAIFEE_DB_AUTO_UPDATE=0` to disable this in offline or fully pinned environments. Set `MCAIFEE_DB_PATH=/path/to/source-db.json` to use a specific cache file.

By default the source database lives at `~/.mcaifee/cache/source-db.json`. Override `cacheDir` or `sourceDbPath` in `~/.mcaifee/config.json`, or set `MCAIFEE_CACHE_DIR` / `MCAIFEE_DB_PATH`.

## Report And Audit

`audit` is an alias of `report`.

```bash
mcaifee report
mcaifee audit
mcaifee report --online
mcaifee audit --format json
```

Reports include:

- Gate decision: `allow`, `needs_manual_review`, or `quarantine`.
- Highest risk level and severity counts.
- Grouped finding counts by class and code.
- Top advisory packages with highest severity, advisory count, fix availability, and sample advisory titles.
- Manifest dependency counts and lifecycle scripts.
- Lockfile package counts, install-script counts, and non-registry sources.
- npm/pnpm advisory findings from `--online` reports when supported lockfiles are present.
- Findings with severity, target, code, message, and evidence.
- Source catalog for npm, OSV, OpenSSF, GitHub, GitLab, deps.dev, Socket.dev, Snyk, Sonatype, CISA KEV, and NVD.
- Recommended next steps.

## Paranoia Mode

Paranoia mode runs an additional Docker install simulation:

```bash
mcaifee npm install --paranoia
mcaifee bun install --paranoia
```

The Docker gate uses:

- `node:22-bookworm-slim` by default.
- Network mode `none` by default.
- Dropped Linux capabilities.
- `no-new-privileges`.
- A read-only project mount.
- A read-only container root filesystem.
- A non-root user, dropped Linux capabilities, pids/memory/CPU limits, and writable tmpfs only for temporary work.
- Fake canary credentials in common environment variables.
- A temporary writable copy of the project inside the container.

It blocks if the simulation writes canary material back into the project copy or creates unexpected files outside the sandbox work area.

Configuration:

```bash
MCAIFEE_PARANOIA=1 mcaifee npm install
MCAIFEE_PARANOIA_IMAGE=node:22-bookworm-slim mcaifee npm install --paranoia
MCAIFEE_PARANOIA_NETWORK=bridge mcaifee npm install --paranoia
```

Use `MCAIFEE_PARANOIA_NETWORK=bridge` only when the sandbox needs registry access.
The default paranoia image is `node:22-bookworm-slim` for npm/pnpm/Yarn and `oven/bun:1` for Bun.

## Finding Classes

Mcaifee currently checks:

- Lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`, pack hooks, and publish hooks.
- Suspicious script content: credential access, network downloads, encoded payloads, inline interpreters, reverse-shell primitives, destructive commands, and persistence paths.
- Package names: Node core-module shadowing and typosquat distance from common packages.
- Dependency specs: local paths, workspace/file specs, Git/SSH specs, HTTP specs, and broad ranges when `--strict-ranges` is enabled.
- Lockfiles: transitive package names, install/build-script flags, tarball source hostnames, missing integrity/checksum signals, duplicate version fanout, and non-registry sources across npm, pnpm, Yarn, and Bun lockfiles.
- Registry metadata in `--online` mode: deprecation, maintainers, package binaries, missing repository/license fields, large dependency fanout, new packages, and package versions newer than the configured minimum age.
- Advisory audit in `--online` mode: `npm audit --json --package-lock-only` for npm lockfiles, `pnpm audit --json` for pnpm lockfiles, and OSV batch lookups for lockfiles without native audit support.

## Data Sources

The current binary performs local checks, lockfile analysis, local source database matching, optional npm registry metadata checks, npm/pnpm advisory audit checks, and optional Docker behavior checks. The report catalog names external feeds that should be used as corroborating evidence when reviewing npm risk:

- npm audit advisory data, queried for npm/pnpm lockfiles in `--online` mode
- OSV.dev, queried for package/version pairs from supported non-npm lockfiles in `--online` mode
- OpenSSF malicious-packages
- GitHub Advisory Database
- GitLab Advisory Database
- deps.dev
- OpenSSF Scorecard
- Socket.dev
- Snyk
- Sonatype OSS Index
- CISA Known Exploited Vulnerabilities
- NVD
- Mend/Renovate datasource metadata
- Phylum research
- ReversingLabs research
- Checkmarx Supply Chain Security
- JFrog security research
- Datadog security research
- Backstabbers Knife Collection
- Aikido Security Intel
- Wiz research
- Koi Security research
- StepSecurity research

Detailed source notes live in `references/npm-security-sources.md`.

A concrete integration plan for using every source appropriately lives in `references/source-integration-plan.md`.

## Malicious npm Fixture

The repository includes `Dockerfile.malicious-test`, which builds Mcaifee, creates a local `evil-pkg@1.0.0`, and gives that package a `postinstall` script that writes `/tmp/mcaifee-pwned`.

Run:

```bash
docker build -f Dockerfile.malicious-test .
```

The expected result is that `mcaifee npm install --mcaifee-fail-on medium` blocks the install before the lifecycle script can create the marker file.

## Exit Codes

- `0`: checks passed or report printed.
- `1`: command/setup error or package-manager staging failure.
- `2`: findings met the configured fail threshold.
- Other values: forwarded package-manager or Docker exit status.

## CI And Release

The release workflow builds Linux x86_64, macOS x86_64, and macOS arm64 binaries for version tags. Release artifacts include SHA-256 checksums, keyless cosign blob signatures/certificates, and GitHub build provenance attestations.

CI includes a focused lockfile parser matrix for `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, and `bun.lockb`, source database import/matching regressions, plus a Docker fixture that verifies lifecycle-script malware is blocked before execution.

Local validation:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked -- -D warnings
cargo build --release --locked
./install.sh --source ./target/release/mcaifee --install-dir /tmp/mcaifee-install --dry-run
docker build -f Dockerfile.malicious-test .
```

## Limits

- npm, pnpm, Yarn, and Bun text lockfiles are parsed for transitive package names, source URLs, integrity/checksum signals, and build-script flags when the lockfile format exposes them. npm lockfiles currently have the richest metadata coverage.
- `--online` advisory audit uses native npm/pnpm audit where available and OSV batch lookups for supported text lockfiles without native audit support.
- `bun.lockb` is a legacy binary lockfile; Mcaifee detects it and requires migration to text `bun.lock` or generation of a Yarn-compatible lockfile for complete static review.
- `mcaifee db update` imports OSV-style npm records, with OpenSSF malicious-packages as the default source. Other external advisory feeds are cataloged for review and corroboration.
- Paranoia mode depends on Docker availability.
- Network-disabled paranoia mode can fail installs that need live registry access.
