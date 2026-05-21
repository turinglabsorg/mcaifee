# Source Integration Plan

Mcaifee should use each npm security source for the signal it is best at, keep provenance for every finding, and avoid flattening weak reputation signals into confirmed malware verdicts.

## Lockfile Coverage

Mcaifee should treat the resolved lockfile as the primary dependency graph source whenever it is present:

- `package-lock.json` and `npm-shrinkwrap.json`: npm dependency graph, tarball URLs, integrity hashes, package metadata, and `hasInstallScript`.
- `pnpm-lock.yaml`: pnpm transitive graph, package snapshots, tarball URLs, integrity hashes, and build/install flags when present.
- `yarn.lock`: Yarn Classic and Berry lock entries, resolved URLs, checksums/integrity, package names, and non-registry sources.
- `bun.lock`: Bun text lockfile, package names, registry/git/tarball sources, integrity-like checksums, and script/build hints exposed by the JSONC lockfile.
- `bun.lockb`: Bun legacy binary lockfile. Detect it and require conversion to text `bun.lock` or a generated Yarn-compatible lockfile before a complete static audit.

## Source Roles

- **Local static checks** are the first gate and always run: package specs, package names, manifest scripts, lockfile sources, integrity, install-script flags, and typosquat/core-module checks.
- **npm registry metadata** is the live package metadata source: maintainers, publish time, deprecation, `dist.tarball`, `dist.integrity`, repository, license, bins, dependency fanout, and registry signatures/provenance when available.
- **npm audit** is npm-native vulnerability coverage for resolved dependency trees. Treat it as authoritative for npm advisory IDs, not as a malware-complete source.
- **OSV.dev** is the cross-ecosystem vulnerability and malicious-package matching layer. Use package/version ecosystem queries and preserve OSV IDs and aliases.
- **OpenSSF malicious-packages** is the primary open malicious-package corpus. Treat exact package/version matches as high-confidence malware evidence.
- **GitHub Advisory Database** is the GHSA layer for vulnerabilities and malware advisories. Use it for aliases, affected ranges, and repository context.
- **GitLab Advisory Database** is an additional advisory corpus, useful for OSV-compatible package/version evidence and dedupe.
- **deps.dev** is dependency graph, license, version, and advisory metadata. Use it for enrichment and graph corroboration, not standalone blocking.
- **Socket.dev** is package behavior and supply-chain risk intelligence. Use it for install scripts, risky APIs, telemetry, maintainer/package health, and malware campaign signals when API access is configured.
- **Snyk** and **Sonatype OSS Index** are secondary vulnerability and component intelligence sources. Use them for corroboration, aliases, and affected-range disagreement checks.
- **CISA KEV** and **NVD** are CVE-level sources. Use them only after mapping npm advisories to CVEs; do not rely on them for npm package/version matching.
- **Vendor threat-intel feeds** such as Phylum, Sonatype research, ReversingLabs, Checkmarx, JFrog, Datadog, Aikido, Wiz, Koi Security, and StepSecurity are fast-moving campaign context. Treat blog-only intelligence as corroborating unless package/version indicators are machine-readable.

## Query Order

1. Build the local graph from `package.json` plus every supported lockfile present.
2. Normalize package identities as `ecosystem:name@version`, preserving source URL, registry host, integrity/checksum, direct/transitive status, and package manager.
3. Run local malware heuristics before any install scripts or package binaries execute.
4. Match the resolved graph against the local Mcaifee source DB created by `mcaifee db update`.
5. Query npm registry metadata for direct dependencies and any transitive packages with elevated local risk.
6. Query npm audit and OSV for the resolved graph.
7. Query confirmed malware corpora: OpenSSF malicious-packages and GitHub malware advisories.
8. Enrich with GitLab, deps.dev, Socket, Snyk, and Sonatype when configured.
9. Correlate CVEs through NVD and CISA KEV only after advisory aliases are known.
10. Add behavior evidence from paranoia mode or tarball inspection for packages that remain ambiguous.

## Implemented Slice

- `mcaifee db update` imports local OSV-style JSON records and defaults to cloning/updating OpenSSF `malicious-packages`.
- `mcaifee db status` reports the local cache path, schema version, update timestamp, and record count.
- `scan`, `report`, `audit`, and package-manager wrappers match exact package versions from lockfiles and exact package specs against the local source DB.
- Package-manager wrappers refresh the default source DB before gated installs when the DB is missing or older than 24 hours.
- Matches are emitted as `source_db_match` findings with source, advisory ID, confidence, aliases, and evidence URL.

## Data Model

Each source result should store:

- `source`: source name and URL.
- `status`: `queried`, `not-configured`, `unavailable`, `stale-cache`, or `error`.
- `fetchedAt`: UTC timestamp.
- `package`: ecosystem, name, version, and direct/transitive relationship.
- `evidence`: advisory ID, malware ID, URL, matched range, source URL, integrity, signature/provenance result, or behavior signal.
- `confidence`: `confirmed`, `strong`, `heuristic`, or `context`.
- `severity`: Mcaifee severity after source-specific normalization.

## Scoring Rules

- Exact malicious package/version match from OpenSSF, GHSA malware, or another machine-readable malware feed is `critical`.
- Credential exfiltration, destructive scripts, reverse shells, HTTP tarballs, and canary leakage are `critical`.
- Git/SSH production dependencies, non-allowed registry hosts, missing integrity on registry tarballs, likely typosquats, and binary legacy lockfiles are `high` or `medium` depending on directness and context.
- CVE-only evidence uses the source CVSS/severity but is raised when CISA KEV confirms exploitation.
- Reputation and health signals never produce `critical` alone; they raise review priority and explain context.

## Operational Requirements

- Cache source responses with TTLs and include cache freshness in reports.
- Dedupe by package, version, advisory ID, and source URL.
- Keep source attribution in text and JSON output.
- Make commercial feeds opt-in via environment variables or config files.
- Fail closed only for local criticals, confirmed malware, and configured fail thresholds. Warn clearly for unavailable optional feeds.
- Never send private package names to external sources unless explicitly enabled for that source.
