# Security policy

This project is a security tool that opens files supplied by exactly the people
it is used to investigate. Its own attack surface matters as much as its
findings, so vulnerability reports are welcome and taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting:

> [Report a vulnerability](https://github.com/lostcharonprivate-del/mobile-app-security-analyzer/security/advisories/new)

Please include a proof-of-concept package or file where possible, the command
you ran, and what you observed. A crash is useful; a crash with the bytes that
caused it is far more useful.

You can expect an acknowledgement within 7 days and an assessment within 30.

## What is in scope

The threat model is *a hostile package handed to the analyzer*. In scope:

- Escaping the extraction sandbox — path traversal, symlinks, hardlinks, device
  or FIFO members, or anything that writes outside the temporary directory.
- Resource exhaustion that survives the declared limits: zip bombs, decompression
  ratios, entry counts, parser loops that do not terminate.
- Any parser (`axml`, `dex`, `arsc`, `macho`, plist, XML) raising something other
  than `ParseError`, hanging, or exhausting memory on malformed input.
- XML external entity resolution, entity expansion, or SSRF from a parsed
  document.
- Injection into a generated report — XSS in the HTML output, an executable URL
  scheme in a reference, or a credential appearing in usable form anywhere in
  the HTML, JSON, title or metadata.
- Command or argument injection into an invoked decompiler.
- **Any network traffic that is not an explicit, `--online`-gated OSV.dev
  library-coordinate lookup.** Package contents, filenames and hashes must never
  leave the machine. If you can make them leave, that is a vulnerability.

## What is not in scope

- Missed detections and false positives. These are correctness issues — please
  file them with the *False positive or false negative* issue template instead.
- Vulnerabilities in apktool, jadx or class-dump. Report those upstream; if the
  sandbox fails to contain them, that part is in scope here.
- The intentionally-vulnerable demo app under `tests/fixtures/`. It is meant to
  be insecure and is never executed.

## Supported versions

The latest released version receives fixes. See [CHANGELOG.md](CHANGELOG.md).

## Using this tool

Analyse only applications you own or have explicit written authorisation to
test. Unauthorised analysis of third-party applications may breach their terms
of service or the law in your jurisdiction.
