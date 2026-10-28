"""Evaluate a request against a policy document.

The precedence is the one that surprises people: **an explicit Deny always wins**, even if a
dozen Allows match, and if nothing matches at all the answer is Deny. Getting that order wrong
is how "we allowed it in the policy" turns into an outage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

from .policy import Policy, Statement, glob_match


class EvaluateError(ValueError):
    """Raised when a request cannot be evaluated."""


@dataclass(frozen=True)
class Request:
    action: str
    resource: str
    context: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.action or ":" not in self.action:
            raise EvaluateError(f"action must look like service:Operation, got {self.action!r}")
        if not self.resource:
            raise EvaluateError("resource must not be empty")

    @property
    def label(self) -> str:
        return f"{self.action} on {self.resource}"

    def as_dict(self) -> dict:
        return {"action": self.action, "resource": self.resource, "context": dict(self.context)}


@dataclass(frozen=True)
class Decision:
    effect: str
    matched_allows: tuple[int, ...]
    matched_denies: tuple[int, ...]
    statements: tuple[Statement, ...]
    reason: str

    @property
    def allowed(self) -> bool:
        return self.effect == "Allow"

    @property
    def decided_by(self) -> int | None:
        if self.matched_denies:
            return self.matched_denies[0]
        if self.matched_allows:
            return self.matched_allows[0]
        return None

    def as_dict(self) -> dict:
        return {
            "effect": self.effect,
            "allowed": self.allowed,
            "reason": self.reason,
            "decided_by": self.decided_by,
            "matched_allows": list(self.matched_allows),
            "matched_denies": list(self.matched_denies),
        }


def evaluate(policy: Policy, request: Request) -> Decision:
    allows: list[int] = []
    denies: list[int] = []
    seen: list[Statement] = []
    for statement in policy.statements:
        if not statement.matches_action(request.action):
            continue
        if not statement.matches_resource(request.resource):
            continue
        if not conditions_match(statement, request.context):
            continue
        seen.append(statement)
        if statement.effect == "Deny":
            denies.append(statement.index)
        else:
            allows.append(statement.index)

    if denies:
        reason = f"explicit deny in statement {denies[0]} overrides {len(allows)} allow(s)"
        return Decision("Deny", tuple(allows), tuple(denies), tuple(seen), reason)
    if allows:
        return Decision(
            "Allow",
            tuple(allows),
            (),
            tuple(seen),
            f"allowed by statement {allows[0]}",
        )
    return Decision(
        "Deny",
        (),
        (),
        (),
        "no statement matched, and the default is deny",
    )


def evaluate_many(policy: Policy, requests: list[Request]) -> list[dict]:
    return [
        {"request": request.as_dict(), **evaluate(policy, request).as_dict()}
        for request in requests
    ]


NEGATED_OPERATORS = {
    "StringNotEquals",
    "StringNotLike",
    "ArnNotLike",
    "NotIpAddress",
}


def conditions_match(statement: Statement, context: dict[str, str]) -> bool:
    """All condition blocks must hold; within a block, values are OR-ed (IAM semantics)."""
    for operator, entries in statement.conditions.items():
        for key, values in entries.items():
            if not _condition_holds(operator, values, context.get(key)):
                return False
    return True


def _condition_holds(operator: str, values: tuple[str, ...], actual: str | None) -> bool:
    if actual is None:
        # A missing context key cannot satisfy a positive condition. For a negated operator
        # the answer flips, because "nothing equals X" is true when there is nothing.
        return operator in NEGATED_OPERATORS
    if operator in ("StringEquals", "StringNotEquals"):
        matched = any(actual == value for value in values)
        return not matched if operator == "StringNotEquals" else matched
    if operator in ("StringLike", "StringNotLike"):
        matched = any(glob_match(value, actual) for value in values)
        return not matched if operator == "StringNotLike" else matched
    if operator in ("ArnLike", "ArnNotLike"):
        matched = any(glob_match(value, actual) for value in values)
        return not matched if operator == "ArnNotLike" else matched
    if operator == "Bool":
        expected = {value.lower() for value in values}
        return actual.lower() in expected
    if operator == "NumericLessThan":
        try:
            return float(actual) < float(values[0])
        except ValueError:
            return False
    if operator == "NumericGreaterThan":
        try:
            return float(actual) > float(values[0])
        except ValueError:
            return False
    if operator in ("IpAddress", "NotIpAddress"):
        try:
            address = ip_address(actual)
        except ValueError:
            return False
        matched = any(address in ip_network(value, strict=False) for value in values)
        return not matched if operator == "NotIpAddress" else matched
    return False
