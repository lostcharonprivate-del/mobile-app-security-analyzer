# Contributing

Thanks for wanting to help. This document covers how to get set up, what a good
change looks like here, and the two rules that are non-negotiable.

## Getting set up

```bash
git clone https://github.com/lostcharonprivate-del/mobile-app-security-analyzer.git
cd mobile-app-security-analyzer
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The APK and IPA fixtures are **not checked in** — they are built from source by
real toolchains so the parsers are exercised against genuine compiler output:

```bash
tests/fixtures/build_android_fixture.sh   # needs the Android SDK (aapt2, d8, apksigner)
tests/fixtures/build_ios_fixture.sh       # needs Xcode
```

If a toolchain is unavailable the tests that need it skip rather than fail, so
you can work on most of the codebase without either SDK. CI builds both.

## The two rules

**1. Nothing about an analysed package may reach the network.** The only request
the tool may ever make is an OSV.dev lookup, gated behind `--online`, carrying a
library name and version and nothing else. No file contents, no hashes, no
filenames, no telemetry, no crash reporting. `tests/test_security_network.py`
enforces this by intercepting the transport and planting a canary string; if
your change makes that test hard to satisfy, the change is wrong, not the test.

**2. Every package is hostile input.** Archive members are attacker-controlled
strings. Never build a path from one without validation, never pass one to a
shell, never trust a declared size. Parsers must terminate, must raise only
`ParseError`, and must not exhaust memory. External tools run with no shell, a
scrubbed environment, a wall-clock timeout and a process-group kill.

## Adding a rule

A rule lives in the analyzer for its category under [`masa/analyzers/`](masa/analyzers/).
A new one needs:

- A stable **rule ID** in the existing scheme (`SEC-`, `MAN-`, `STO-`, `NET-`,
  `CRY-`, `WEB-`, `PRI-`, `BIN-`, `IOS-`). IDs are public API — users suppress
  by them with `--disable-rule`, so don't rename one without a deprecation.
- A **severity**, an **OWASP Mobile Top 10 ID**, a **CWE**, a **MASVS control
  group** and a **confidence** level.
- **Plain-language text.** "What was found" explains why it matters to someone
  who is not a mobile security specialist; "How to fix it" is actionable. Write
  for the developer who has to fix it, not for the scanner that found it.
- **Two tests**: one asserting it fires on the vulnerable fixture, and one
  asserting it stays silent on correct usage. The fixture's `SecureHelper` class
  uses the same APIs correctly on purpose — add your safe case there.
- A row in the README table if it introduces a new category of check.

If a rule is bypassable or matches something ambiguous, say so in the finding
text. A report that overclaims is worse than no report.

### Absences are not defects

Missing root detection, anti-debugging and obfuscation are reported at **Low**,
and each says explicitly that it is an absent hardening measure rather than a
vulnerability. Keep new "you should have X" findings in that shape.

## Style

- Python 3.11+, standard library first. The three runtime dependencies (typer,
  rich, jinja2) are the budget; adding a fourth needs a good argument.
- The decompilation layer stays **pure Python**. apktool and jadx add coverage
  when present; nothing may start requiring them.
- Type hints on public functions. `from __future__ import annotations` at the top.
- Match the surrounding code's comment density: comments explain *why*, not what.

## Pull requests

Run `pytest` before opening one, fill in the template, and keep the change
focused. A PR that adds a rule and refactors the scorer is two PRs.

## Reporting security issues

Not here — see [SECURITY.md](SECURITY.md) for private reporting.
