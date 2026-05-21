# Mcaifee Project Notes

## Features

- `mcaifee` is a Rust CLI wrapper and scanner for pre-install npm/pnpm/yarn/bun dependency risk checks.
- It audits npm package specs, `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, and legacy `bun.lockb` detection.
- It flags malware and supply-chain indicators including lifecycle install scripts, local or non-registry sources, HTTP tarballs, missing integrity hashes, Node core-module shadowing, and likely typosquats of common packages.
- `mcaifee db update` builds a local OSV-style source database, defaulting to OpenSSF `malicious-packages`; scans emit `source_db_match` findings for exact package/version matches.
- Wrapper mode auto-updates the default source database before gated installs when it is missing or older than 24 hours; set `MCAIFEE_DB_AUTO_UPDATE=0` only for offline or pinned tests.
- `--online` uses `npm view` for registry metadata without executing package code.
- `--fail-on <severity>` exits with status `2` when findings meet or exceed the configured threshold.
- Wrapper mode supports `mcaifee npm ...`, `mcaifee pnpm ...`, `mcaifee yarn ...`, and `mcaifee bun ...`.
- Shell integration supports `mcaifee shell-init`, `mcaifee shell-disable`, and `mcaifee shell-status` so plain `npm`, `pnpm`, `yarn`, and `bun` calls can be wrapped in the current shell.
- Report mode supports `mcaifee report` and alias `mcaifee audit`, with text or JSON output.
- `--paranoia` or `MCAIFEE_PARANOIA=1` runs an extra Docker install simulation with network disabled by default, fake canary credentials, dropped capabilities, and a read-only project mount.
- Wrapper logs print an ASCII Mcaifee banner before gated package-manager commands.

## Data Sources

- Current checks are local heuristics, local source database matches, npm registry metadata via `npm view`, lockfile/package.json analysis, transitive npm/pnpm/Yarn/Bun lockfile signals, and optional Docker behavior analysis.
- Recommended advisory sources for review, corroboration, and direct feed integrations are OSV.dev, npm audit registry advisory endpoints, OpenSSF `ossf/malicious-packages`, GitHub Advisory Database, GitLab Advisory Database, deps.dev, Socket.dev, Snyk, Sonatype OSS Index, CISA KEV, NVD, and vendor threat-intel feeds listed in `references/npm-security-sources.md`.

## Distribution

- GitHub Releases are built by `.github/workflows/release.yml` on `v*` tags.
- Release assets target Linux x86_64, macOS x86_64, and macOS Apple Silicon.
- `install.sh` installs the correct release asset for Linux/macOS x86_64/arm64, supports custom install directories, local source smoke tests, and optional shell-init guidance.
- `install.sh --shell-init <shell>` installs a persistent shell startup block; `--shell-disable <shell>` removes it.

## Validation

- Rust validation: `cargo fmt --check`, `cargo test --locked`, `cargo clippy --locked -- -D warnings`, and `cargo build --release --locked`.
- Installer validation: `./install.sh --source ./target/release/mcaifee --install-dir /tmp/mcaifee-install --dry-run`.
- Skill validation: `quick_validate.py` against the skill root.
- Malicious npm gate test: `docker build -f Dockerfile.malicious-test .`.
- Lockfile parser CI: `.github/workflows/ci.yml` runs a focused matrix for npm package lock, npm shrinkwrap v1, pnpm, Yarn, Bun text lock, and Bun binary lock detection.
- Source DB validation: unit tests cover OSV import, package-lock exact version matching, and the 24-hour wrapper refresh window.
- Paranoia mode requires Docker on the host; set `MCAIFEE_PARANOIA_NETWORK=bridge` only when a networked sandbox is explicitly needed.

## Architecture

- The agent skill entrypoint is `SKILL.md`.
- The CLI implementation lives in `src/main.rs`.
- npm threat-model reference material lives in `references/npm-threat-model.md`.
- External source catalog lives in `references/npm-security-sources.md`.
- Source integration plan lives in `references/source-integration-plan.md`.
- The malicious npm Docker test creates a local tarball with a `postinstall` script and verifies that `mcaifee npm install --mcaifee-fail-on medium` blocks before npm can run lifecycle code.
