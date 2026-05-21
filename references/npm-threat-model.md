# npm Threat Model for Mcaifee

## Primary Threats

- Lifecycle script execution: `preinstall`, `install`, `postinstall`, `prepare`, and publish-time scripts can execute arbitrary shell commands.
- Typosquatting and dependency confusion: malicious packages mimic popular names or exploit private package names through registry precedence.
- Maintainer compromise: trusted packages can publish malicious versions after account/token compromise.
- Tarball/source mismatch: registry tarballs can contain code that is not visible in the linked repository.
- Binary downloaders: packages can fetch platform binaries or payloads during install.
- Credential and environment exfiltration: malicious scripts often target `.npmrc`, npm tokens, GitHub tokens, cloud credentials, SSH keys, wallet files, and CI secrets.
- Registry drift: lockfiles can point to non-default registries, Git URLs, local files, or HTTP tarballs.
- Agent-targeted prompt injection: package READMEs, install logs, or generated files can contain instructions aimed at making coding agents run unsafe commands.

## Evidence Sources

- `package.json`: direct dependency specs, lifecycle scripts, `bin`, `publishConfig`, and registry overrides.
- `package-lock.json` or `npm-shrinkwrap.json`: exact versions, tarball URLs, integrity hashes, `hasInstallScript`, and transitive changes.
- npm registry metadata: maintainers, publish times, deprecation, dist tarball, integrity, repository, license, dependencies, and scripts.
- Tarball contents: packed files, package manifest, hidden payloads, generated files, encoded blobs, and mismatch with source repository.
- Advisory databases: npm audit, OSV, GitHub Security Advisories, and vendor malware feeds if available.
- Provenance and signatures: npm registry ECDSA signatures and npm package provenance attestations when supported.
- Repository health: recent maintainer changes, unexpected repo transfer, release automation, OpenSSF Scorecard, branch rules, and signed releases.

## Manual Review Triggers

- Any lifecycle script in a new direct dependency.
- Scripts that invoke shell interpreters, network download tools, encoded payloads, credential paths, `/tmp`, startup folders, or environment-variable dumps.
- New or low-download packages that are name-similar to established packages.
- A package published in the last 7 days, especially if it changes install behavior.
- Non-npm registry URLs, Git dependencies, local file dependencies, missing integrity hashes, or HTTP URLs.
- Tarballs with generated/minified install code that is absent from the repository.
- Packages with a new maintainer, single maintainer, deprecated status, or recent ownership transfer.

## Useful Commands

```bash
npm view <pkg>@<version> --json
npm audit --json
npm audit signatures --json --include-attestations
npm pack --ignore-scripts <pkg>@<version>
osv-scanner scan source --lockfile=package-lock.json
```

## External References

- npm audit and signature verification: https://docs.npmjs.com/cli/v11/commands/npm-audit/
- npm install script behavior and `ignore-scripts`: https://docs.npmjs.com/cli/v11/commands/npm-install/
- npm package provenance: https://docs.npmjs.com/viewing-package-provenance
- npm registry signatures: https://docs.npmjs.com/verifying-registry-signatures
- OSV API and vulnerability database: https://osv.dev/
- OSV-Scanner lockfile scanning: https://google.github.io/osv-scanner/usage/scan-source
- OpenSSF Scorecard: https://scorecard.dev/

See `references/npm-security-sources.md` for a broader source catalog.
