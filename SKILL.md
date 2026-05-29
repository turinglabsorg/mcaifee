---
name: mcaifee
description: Guard npm installs and dependency changes by auditing npm packages, package.json manifests, npm/pnpm/Yarn/Bun lockfiles, lifecycle scripts, registry metadata, npm signatures/provenance, OSV/npm advisories, and malware supply-chain indicators before installing, upgrading, or accepting generated code that adds npm dependencies. Use when an agent is asked to install npm packages, add or upgrade JavaScript dependencies, review npm dependency PRs, investigate suspicious package behavior, or create a supply-chain security gate for npm malware and dependency risk.
---

# Mcaifee

## Goal

Use this skill as a pre-install and pre-merge gate for JavaScript dependencies. The goal is to reduce malware and supply-chain risk before any package lifecycle script or package code is executed.

## Non-Negotiables

- Do not run `npm install`, package binaries, or package lifecycle scripts before the gate is complete.
- Prefer metadata, lockfile, tarball, and source inspection over executing package code.
- When install simulation is unavoidable, use a disposable directory and `--ignore-scripts`.
- Treat vulnerability-only scans as incomplete; npm malware often appears first as install-script behavior, typosquatting, compromised maintainer releases, suspicious tarballs, or registry/source mismatch.

## Fast Path

Use `mcaifee` as a package-manager wrapper:

```bash
mcaifee npm install
mcaifee npm install left-pad
mcaifee pnpm add react
mcaifee yarn add vite
mcaifee bun add zod
```

To wrap plain package-manager commands in the current shell:

```bash
eval "$(mcaifee shell-init --shell zsh)"
pnpm install --paranoia
bun install --paranoia
eval "$(mcaifee shell-disable --shell zsh)"
```

For a stronger Docker sandbox pass:

```bash
mcaifee npm install --paranoia
```

`--paranoia` runs an install simulation inside Docker with network disabled by default, fake canary credentials, dropped Linux capabilities, and a read-only mount of the project. It blocks if lifecycle behavior creates files outside the project sandbox or writes canary secret material back into the project.

For scanner-only use:

```bash
mcaifee scan --package-json package.json --lockfile package-lock.json
```

Refresh the local malicious-package source database when network access is allowed:

```bash
mcaifee db update
mcaifee db status
```

The package-manager wrapper automatically runs a source database update before gated installs when the default database is missing or older than 24 hours. User policy lives in `~/.mcaifee/config.json`, and cache data lives in `~/.mcaifee/cache/`. Use `mcaifee config init` and `mcaifee config status` to create or inspect policy. Use `MCAIFEE_DB_AUTO_UPDATE=0` only for offline or pinned test environments.

The default minimum package version age is 7 days. Override it with `minimumVersionAgeHours` in config, `MCAIFEE_MIN_VERSION_AGE_HOURS`, `--min-version-age-hours`, or wrapper flag `--mcaifee-min-version-age-hours`. Use `0` only for an explicit bypass of the publish-age gate.

Registry allowlists and command timeout policy can also live in config. Use `allowRegistryHosts`, `MCAIFEE_ALLOW_REGISTRY_HOSTS`, `--allow-registry-host`, or wrapper flag `--mcaifee-allow-registry-host` for private registries. Use `timeoutSeconds`, `MCAIFEE_TIMEOUT`, `--timeout`, or wrapper flag `--mcaifee-timeout` to cap registry, audit, and advisory queries. Use `mcaifee doctor` to verify config, cache, logs, source DB freshness, and package-manager tool availability.

Every invocation writes a best-effort JSONL event to `~/.mcaifee/logs/` by default, with redacted arguments, cwd, executable path, timestamps, duration, exit code, and success state. Disable with `logInvocations: false` or `MCAIFEE_LOG_INVOCATIONS=0`; override the destination with `logDir` or `MCAIFEE_LOG_DIR`. Logs are retained for 30 days by default; override with `logRetentionDays` or `MCAIFEE_LOG_RETENTION_DAYS`, and inspect them with `mcaifee logs status`, `mcaifee logs tail`, or `mcaifee logs prune`.

For a complete review artifact:

```bash
mcaifee report --online
mcaifee audit --online --format json
```

`audit` is an alias of `report`.

Reports include a gate decision (`allow`, `needs_manual_review`, or `quarantine`), grouped finding summaries, and advisory package rollups when npm/pnpm audit data is available.

For proposed packages:

```bash
mcaifee scan react@18.2.0 react-dom@18.2.0 --online
```

Use `--online` only when network access is allowed. It calls `npm view` for live registry metadata, runs supported package-manager advisory audits (`npm audit` for npm lockfiles, `pnpm audit` for pnpm lockfiles), and queries OSV for supported lockfiles without native audit support. It does not execute package code.

If the `mcaifee` binary or skill is not installed in a Codex session, install both with:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/mcaifee/main/install.sh | sh -s -- --agent-skill --path-link
```

For local development, use the release artifact from `https://github.com/turinglabsorg/mcaifee/releases` or run from source with `cargo run --`.

Mcaifee's built-in checks are local heuristics, local source database matches, registry metadata, npm/pnpm advisory audit, OSV advisory lookup for supported text lockfiles, lockfile analysis, and optional Docker behavior analysis. It parses npm, pnpm, Yarn, and Bun text lockfiles; `bun.lockb` is detected as a binary legacy lockfile that must be converted for full static audit. For advisory databases beyond npm/pnpm audit and OSV, use GitHub Advisory Database and OpenSSF malicious-packages as supporting evidence; do not treat any single DB as complete for npm malware. Read `references/npm-security-sources.md` and `references/source-integration-plan.md` when choosing external security feeds or implementing source integrations.

To verify the install gate against a local malicious npm package:

```bash
docker build -f Dockerfile.malicious-test .
```

## Workflow

1. Identify the change surface:
   - New package specs requested by the user or generated code.
   - `package.json` dependency sections.
   - Lockfile additions in `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, or `bun.lockb`.
   - Changed versions, changed source/resolved URLs, changed integrity/checksum hashes, and new install/build-script entries.

2. Collect evidence:
   - Prefer `mcaifee npm ...`, `mcaifee pnpm ...`, `mcaifee yarn ...`, or `mcaifee bun ...` instead of calling the package manager directly.
   - Run `mcaifee db update` when network access is allowed so confirmed malicious package records are available locally; wrapper mode also refreshes the default database automatically when it is older than 24 hours.
   - Run `mcaifee scan` against package specs, `package.json`, and lockfiles for review-only tasks.
   - Run `mcaifee report --online` in projects that already have a supported lockfile so npm/pnpm audit advisory findings are included in the Mcaifee report.
   - Run `npm audit signatures --json --include-attestations` when packages are already downloaded and npm supports registry signatures/provenance for the registry.
   - If `osv-scanner` is available, scan lockfiles with OSV in addition to npm audit.
   - For unclear packages, inspect registry metadata with `npm view <pkg>@<version> --json`, including publish time against the configured minimum version age.
   - For tarball inspection, use a disposable directory and `npm pack --ignore-scripts <pkg>@<version>`, then inspect the archive without running code.

3. Triage risk:
   - **Critical**: known malicious package/version, explicit credential exfiltration, destructive lifecycle script, reverse shell behavior, HTTP tarball, or registry/signature/provenance failure for a package that should verify.
   - **High**: suspicious lifecycle script, likely typosquat of a popular package, core-module shadowing (`fs`, `path`, `crypto`, etc.), missing lockfile integrity for registry tarballs, or untrusted non-npm tarball/git source in production dependencies.
   - **Medium**: install scripts requiring manual review, package versions newer than the configured minimum age, deprecated package, single-maintainer sensitive dependency, non-default registry, or binary downloader.
   - **Low**: missing repository/license metadata, broad version range, unusually large dependency fanout, or package with CLI/bin entry that needs extra review.

4. Decide:
   - **Allow** only when no high/critical findings remain and the package is necessary.
   - **Needs manual review** for medium findings, install scripts, unusual registries, new packages, or provenance gaps.
   - **Quarantine** for high/critical findings. Do not install. Prefer removing the dependency, using an established alternative, or pinning a known-good version after review.

5. Harden the install path:
   - Prefer `mcaifee npm ci` or `mcaifee npm install --paranoia` for first pass dependency materialization.
   - Approve lifecycle scripts package-by-package only when their purpose is understood.
   - Commit lockfile changes and review `resolved`, `integrity`, and `hasInstallScript` diffs.
   - Pin direct dependencies when risk is elevated.
   - Use private registry allowlists for production builds when available.

## Reporting Format

Return a concise gate result:

```text
Decision: allow | needs manual review | quarantine
Scope: package specs, package.json, lockfiles
Highest risk: critical | high | medium | low | none
Evidence:
- [severity] package/source: finding and why it matters
Actions:
- Required follow-up before install or merge
```

## References

Read `references/npm-threat-model.md` when the task involves a suspicious package, install-script review, dependency confusion, provenance/signature verification, or explaining why a package was blocked.

Read `references/npm-security-sources.md` when the task involves vulnerability databases, malicious package corpora, threat-intel feeds, source prioritization, or adding new external data integrations.

Read `references/source-integration-plan.md` when the task involves implementing source APIs, scoring source evidence, or deciding which registry/advisory/threat-intel source should be authoritative for a finding.
