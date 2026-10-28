"""Reports for a decision, a policy review, or a batch of requests."""

from __future__ import annotations

import json

from .evaluate import Decision
from .review import SEVERITY_ORDER, Review

BADGES = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def short_resource(resource: str, width: int) -> str:
    """Compress an ARN so two resources stay distinguishable in a narrow column."""
    text = resource
    if text.startswith("arn:"):
        parts = text.split(":", 5)
        if len(parts) == 6:
            text = f"{parts[2]}:{parts[5]}"
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def render_decision(decision: Decision, *, request_label: str = "", title: str = "Request") -> str:
    lines = [f"{title}: {request_label}".rstrip(": "), "=" * 66]
    lines.append(f"effect      {decision.effect}")
    lines.append(f"reason      {decision.reason}")
    if decision.matched_denies:
        lines.append(f"denies      {', '.join(str(index) for index in decision.matched_denies)}")
    if decision.matched_allows:
        lines.append(f"allows      {', '.join(str(index) for index in decision.matched_allows)}")
    if decision.statements:
        lines.append("")
        lines.append("Matched statements")
        for statement in decision.statements:
            lines.append(f"  {statement.label}")
    return "\n".join(lines)


def render_review(result: Review, *, title: str = "Policy review") -> str:
    lines = [title, "=" * 66]
    lines.append(
        f"risk {result.risk} points (grade {result.grade})   "
        f"critical {result.counts['critical']}   high {result.counts['high']}   "
        f"medium {result.counts['medium']}   low {result.counts['low']}"
    )
    if result.clean:
        lines.append("")
        lines.append("No findings. Every statement is scoped and conditional.")
        return "\n".join(lines)
    current = None
    for finding in result.findings:
        if finding.severity != current:
            current = finding.severity
            lines.append("")
            lines.append(BADGES[current])
        location = f"statement {finding.statement}" if finding.statement else "policy"
        lines.append(f"  [{finding.code}] {location}: {finding.message}")
        lines.append(f"      fix: {finding.hint}")
    return "\n".join(lines)


def render_markdown(result: Review, *, title: str = "Policy review") -> str:
    lines = [f"### {title}", ""]
    lines.append(
        f"**Risk {result.risk} points (grade {result.grade})** - "
        f"{result.counts['critical']} critical, {result.counts['high']} high, "
        f"{result.counts['medium']} medium, {result.counts['low']} low."
    )
    lines.append("")
    lines.append("| Severity | Statement | Finding | Fix |")
    lines.append("| --- | ---: | --- | --- |")
    for finding in result.findings:
        lines.append(
            f"| {BADGES[finding.severity]} | {finding.statement or '-'} | "
            f"{finding.message.replace('|', '/')} | {finding.hint.replace('|', '/')} |"
        )
    if result.clean:
        lines.append("| - | - | No findings | - |")
    return "\n".join(lines)


def render_review_json(result: Review) -> str:
    return json.dumps(result.as_dict(), indent=2)


def render_batch(rows: list[dict]) -> str:
    lines = [
        "Batch policy check",
        "=" * 92,
        f"{'action':<30}{'resource':<44}{'expect':>8}{'actual':>8}{'':>6}",
    ]
    for row in rows:
        expected = row.get("expect") or "-"
        status = ""
        if expected in ("Allow", "Deny"):
            status = "PASS" if row["effect"] == expected else "FAIL"
        resource = short_resource(row["request"]["resource"], 43)
        lines.append(
            f"{row['request']['action'][:29]:<30}{resource:<44}"
            f"{expected:>8}{row['effect']:>8}{status:>6}"
        )
    failures = sum(1 for row in rows if row.get("expect") and row["effect"] != row["expect"])
    lines.append("")
    lines.append(
        f"requests {len(rows)}   allowed {sum(1 for row in rows if row['effect'] == 'Allow')}"
        f"   denied {sum(1 for row in rows if row['effect'] == 'Deny')}"
        f"   mismatches {failures}"
    )
    return "\n".join(lines)


def render_matrix(actions: list[str], resources: list[str], decisions: list[list[Decision]]) -> str:
    """Grid keyed by column index, with the resource list underneath.

    Full ARNs never fit side by side in a terminal, and truncating them makes two
    columns look identical, so the header uses R1..Rn and the legend carries the ARNs.
    """
    width = 8
    labels = [f"R{index}" for index in range(1, len(resources) + 1)]
    lines = ["Decision matrix", "=" * (24 + width * len(resources))]
    lines.append(f"{'action':<24}" + "".join(f"{label:>{width}}" for label in labels))
    for action, row in zip(actions, decisions, strict=True):
        cells = "".join(f"{decision.effect:>{width}}" for decision in row)
        lines.append(f"{action:<24}{cells}")
    lines.append("")
    lines.append("resources")
    for label, resource in zip(labels, resources, strict=True):
        lines.append(f"  {label}  {resource}")
    return "\n".join(lines)


def severity_counts(result: Review) -> dict[str, int]:
    return {severity: result.counts.get(severity, 0) for severity in SEVERITY_ORDER}
