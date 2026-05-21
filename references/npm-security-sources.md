# npm Security Sources

Use multiple sources because no single vulnerability or malware database is complete for npm supply-chain risk.

## Machine-Usable Sources

- **npm audit advisory endpoints**: npm-native vulnerability advisory source used by `npm audit`. Best for vulnerabilities in npm dependency trees.
- **OSV.dev API and data dumps**: cross-ecosystem vulnerability database with npm support and package/version matching.
- **OpenSSF malicious-packages**: malicious package reports in OSV format; useful for typosquatting, account takeover, dependency confusion, and install-time malware reports.
- **GitHub Advisory Database**: vulnerability and malware advisories, especially useful when linked to GitHub repositories and GHSA IDs.
- **OpenSSF Package Analysis**: behavioral analysis project for packages; useful as a reference for runtime behavior signals and feed integration.
- **OpenSSF Scorecard**: repository health and maintainer practice signals; not a malware DB, but useful for risk scoring.
- **Socket.dev package scores/API**: supply-chain risk signals for npm packages, including install scripts, telemetry, risky APIs, and maintainer/package health when available.
- **Snyk Vulnerability DB**: broad vulnerability coverage and package metadata, useful as a secondary advisory source.
- **Sonatype OSS Index / Lift**: vulnerability and component intelligence for open source packages.
- **deps.dev API**: Google-hosted dependency metadata, versions, advisories, licenses, and dependency graph signals.
- **GitLab Advisory Database**: package vulnerability advisories, useful as another OSV-compatible source.
- **Mend.io / Renovate datasource metadata**: version and release metadata, deprecation, replacement, and advisory context when available.
- **CISA KEV**: known exploited vulnerabilities; mostly CVE-level, useful when npm advisories map to CVEs.
- **NVD CVE**: CVE metadata. Use as secondary evidence because npm package/version mapping can be weaker than OSV/npm-native data.

## Malware and Threat Intel Sources

- **OpenSSF malicious-packages repository**: primary open malicious package corpus.
- **GitHub Advisory Database filtered by malware**: npm malware reports tied to GHSA records.
- **Socket.dev research and package pages**: ongoing npm malware, sabotage, and supply-chain abuse findings.
- **Phylum research / package intelligence**: supply-chain malware reports and package risk analysis.
- **Sonatype security research**: malicious package campaigns and npm malware reports.
- **ReversingLabs reports**: malicious package campaigns and repository malware trends.
- **Checkmarx Supply Chain Security reports**: npm malware campaigns and typosquatting findings.
- **JFrog security research**: npm malware and vulnerable package reports.
- **Datadog malicious software package dataset/research**: useful historical corpus and campaign context.
- **Backstabbers Knife Collection**: historical malicious npm, PyPI, and RubyGems package corpus.
- **Aikido Security Intel / safe-chain research**: npm campaign writeups and advisories when available.
- **Wiz, Koi Security, StepSecurity, and other supply-chain research feeds**: useful for fast-moving npm compromise campaigns; treat as corroborating sources unless machine-readable data is available.

## Registry and Package Metadata

- **npm registry metadata** via `npm view <pkg>@<version> --json`: maintainers, publish time, deprecation, dist tarball, integrity, repository, license, scripts, and dependencies.
- **npm registry signatures and provenance**: verify when supported for packages already fetched.
- **Package tarball inspection**: compare tarball contents to repository source, scripts, binaries, generated/minified code, and encoded payloads.
- **Repository metadata**: release history, maintainer changes, repository transfer, branch rules, signed tags/releases, issue activity, and CI provenance.

## Recommended Source Order

1. Local static checks: package specs, `package.json`, lockfile, lifecycle scripts, tarball URL, integrity, typosquat/core-module shadowing.
2. npm-native checks: `npm audit --json`, npm signatures, npm provenance, `npm view`.
3. OSV checks: OSV API or `osv-scanner` against lockfiles/SBOMs.
4. Malicious package corpus: OpenSSF malicious-packages and GitHub malware advisories.
5. Behavioral checks: `mcaifee --paranoia`, tarball inspection, and isolated package install simulation.
6. Reputation and health signals: OpenSSF Scorecard, Socket/Snyk/Sonatype/deps.dev/GitHub/GitLab advisory context.

## Implementation Notes

- Prefer official APIs or cloned data repositories over scraping web pages.
- Cache source responses with timestamps and source URLs so decisions are auditable.
- Track source freshness; stale malware feeds should warn, not silently pass.
- De-duplicate findings by package, version, source, and advisory ID.
- Preserve source attribution in output so users can distinguish confirmed advisories from heuristics.
- Treat threat-intel blogs as corroborating evidence unless they publish package/version machine-readable indicators.
