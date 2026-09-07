"""Risk scoring.

The score exists to order and communicate, not to be precise — there is no
defensible way to turn static findings into a real-world risk number. The model
is therefore deliberately simple and fully explainable:

* each finding contributes `severity weight x confidence weight`;
* a single rule's total contribution is capped, so one noisy rule (fifty
  hardcoded strings, say) cannot dominate an app that is otherwise sound;
* the total is mapped through a saturating curve to 0-100, because the difference
  between twenty and forty serious findings is not what a reader needs from a
  headline number.

`explain()` returns the arithmetic so a report can show its work.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from masa.models import Finding, Severity

# Contribution from a single rule is capped at this multiple of its unit weight.
_RULE_CAP_MULTIPLIER = 3.0

# Controls how fast the curve saturates. At raw == SCALE the score is ~63.
_SCALE = 30.0

_GRADES = (
    (10.0, "A", "No significant issues found"),
    (25.0, "B", "Minor issues; routine hardening work"),
    (45.0, "C", "Meaningful issues that should be scheduled"),
    (70.0, "D", "Serious issues; fix before the next release"),
    (100.1, "F", "Critical issues; do not ship in this state"),
)


@dataclass
class ScoreBreakdown:
    raw: float = 0.0
    score: float = 0.0
    grade: str = "A"
    grade_label: str = ""
    per_rule: dict[str, float] = field(default_factory=dict)
    capped_rules: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "raw": round(self.raw, 2),
            "score": round(self.score, 1),
            "grade": self.grade,
            "grade_label": self.grade_label,
            "severity_counts": dict(self.severity_counts),
            "capped_rules": list(self.capped_rules),
        }


def score_findings(findings: list[Finding]) -> ScoreBreakdown:
    """Compute the 0-100 risk score. Higher means more risk."""
    breakdown = ScoreBreakdown()
    breakdown.severity_counts = {severity.label: 0 for severity in Severity}

    per_rule: dict[str, float] = {}
    unit_weight: dict[str, float] = {}

    for finding in findings:
        breakdown.severity_counts[finding.severity.label] += 1
        contribution = finding.severity.weight * finding.confidence.weight
        per_rule[finding.rule_id] = per_rule.get(finding.rule_id, 0.0) + contribution
        unit_weight[finding.rule_id] = max(
            unit_weight.get(finding.rule_id, 0.0), contribution
        )

    total = 0.0
    for rule_id, accumulated in per_rule.items():
        cap = unit_weight[rule_id] * _RULE_CAP_MULTIPLIER
        if accumulated > cap:
            breakdown.capped_rules.append(rule_id)
            accumulated = cap
        per_rule[rule_id] = accumulated
        total += accumulated

    breakdown.raw = total
    breakdown.per_rule = per_rule
    breakdown.score = 100.0 * (1.0 - math.exp(-total / _SCALE))
    breakdown.capped_rules.sort()

    for threshold, grade, label in _GRADES:
        if breakdown.score < threshold:
            breakdown.grade = grade
            breakdown.grade_label = label
            break
    return breakdown


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first; within a severity, most confident first, then stable."""
    return sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            -f.confidence.weight,
            int(f.owasp[1:]),
            f.rule_id,
        ),
    )


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Drop findings that are identical in rule and evidence locations."""
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        key = finding.fingerprint
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def explain() -> str:
    """One-paragraph description of the model, for the report."""
    return (
        "Each finding contributes its severity weight (Critical 10, High 7, "
        "Medium 4, Low 1.5, Info 0) multiplied by a confidence factor (High 1.0, "
        "Medium 0.7, Low 0.4). A single rule contributes at most three times its "
        f"unit weight, so one noisy rule cannot dominate. The total is mapped to "
        f"0-100 through 100 x (1 - e^(-total/{_SCALE:.0f})), which saturates: the "
        "score is a communication device for ordering and triage, not a measurement "
        "of real-world risk."
    )
