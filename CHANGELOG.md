# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Rule IDs are treated as public API: users suppress findings by ID with
`--disable-rule`, so a removed or renamed ID is a breaking change.

## [Unreleased]

### Added
- Standard GitHub repository layout: CI workflow, issue and pull request
  templates, Dependabot configuration, security policy and contribution guide.
- Screenshots of the terminal output and HTML report under `docs/images/`.

## [1.0.0] - 2026-09-07

### Added
- Static analysis of Android APKs and iOS IPAs, mapped to OWASP Mobile Top 10
  (2024) and MASVS.
- Eleven analyzer plugins: `archive`, `secrets`, `manifest`, `storage`,
  `network`, `crypto`, `webview`, `privacy`, `binary`, `dependencies`,
  `ios_config`.
- Pure-Python decompilation layer — binary `AndroidManifest.xml` (AXML), DEX
  with register constant tracking, `resources.arsc`, and Mach-O with Objective-C
  class and selector recovery. apktool, jadx and class-dump are optional.
- Terminal, self-contained HTML and versioned JSON report formats.
- Risk scoring: severity × confidence with a per-rule cap and a saturating curve
  to a 0–100 score and an A–F grade.
- CI-oriented exit codes (`0` clean, `1` findings at or above `--fail-on`,
  `2` package refused, `3` unexpected error).
- Hardened ingestion: archive validation before extraction, a mode-0700 sandbox
  wiped after use, and refusal of path traversal, symlink members, zip bombs and
  oversized entries.
- Subprocess isolation for external decompilers: no shell, scrubbed environment,
  wall-clock timeout, process-group kill.
- Offline by default. OSV.dev dependency lookups require `--online` and transmit
  only a library coordinate.
- Docker image with apktool and jadx bundled, running with `network_mode: none`,
  a read-only root filesystem, all capabilities dropped and an unprivileged user.
- Intentionally-vulnerable Android and iOS fixtures built by the real toolchains,
  and a 439-test suite weighted towards the tool's own attack surface.

[Unreleased]: https://github.com/lostcharonprivate-del/mobile-app-security-analyzer/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/lostcharonprivate-del/mobile-app-security-analyzer/releases/tag/v1.0.0
