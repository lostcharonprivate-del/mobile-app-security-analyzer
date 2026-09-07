## What this changes

<!-- One paragraph. Link the issue it closes, if any. -->

## Why

<!-- What was wrong or missing. For a new rule, the insecure pattern it catches. -->

## Checklist

- [ ] `pytest` passes locally
- [ ] New behaviour has tests; a new rule has both a positive and a negative case
- [ ] No credential, hash or filename from an analysed package can reach the network
- [ ] Untrusted input stays untrusted — no new path built from archive member names
- [ ] `masa rules` output and the README tables still match reality
- [ ] Findings state their confidence, and low-confidence ones say what else the match could be

## For a new rule

| | |
|---|---|
| Rule ID | |
| Severity | |
| OWASP / CWE / MASVS | |
| Confidence | |

<!-- What legitimate code could trigger this, and how the rule avoids it: -->
