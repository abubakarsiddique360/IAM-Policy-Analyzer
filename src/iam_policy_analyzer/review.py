"""Review a policy the way a security reviewer would: what could this grant, and how badly?

Each finding is tied to a statement index, so a review comment can point at the line that
matters instead of the whole document. Severity is deliberately blunt - wildcards and
privilege-escalation primitives are the things that turn an incident into a breach.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .policy import Policy, Statement, glob_match

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_POINTS = {"critical": 30, "high": 15, "medium": 8, "low": 3}

# Actions that let a principal give itself more power. Any of these on a wildcard resource is
# the classic escalation path.
ESCALATION_ACTIONS = (
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AddUserToGroup",
    "iam:PassRole",
    "sts:AssumeRole",
)

SENSITIVE_SERVICES = ("iam", "organizations", "kms", "secretsmanager", "sts")


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    statement: int
    message: str
    hint: str

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "statement": self.statement,
            "message": self.message,
            "hint": self.hint,
            "points": self.points,
        }


@dataclass(frozen=True)
class Review:
    findings: tuple[Finding, ...]
    risk: int
    grade: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.findings

    def at_or_above(self, severity: str) -> list[Finding]:
        limit = SEVERITY_ORDER[severity]
        return [item for item in self.findings if SEVERITY_ORDER[item.severity] <= limit]

    def should_fail(self, fail_on: str) -> bool:
        if fail_on == "never":
            return False
        return bool(self.at_or_above(fail_on))

    def as_dict(self) -> dict:
        return {
            "risk": self.risk,
            "grade": self.grade,
            "counts": self.counts,
            "findings": [item.as_dict() for item in self.findings],
        }


def review(policy: Policy) -> Review:
    findings: list[Finding] = []
    for statement in policy.statements:
        findings.extend(_review_statement(statement))
    if not policy.statements:
        findings.append(
            Finding("empty-policy", "medium", 0, "policy has no statements",
                    "remove the policy or give it a purpose")
        )
    if policy.version not in ("2012-10-17", "2008-10-17"):
        findings.append(
            Finding("unknown-version", "low", 0, f"unrecognised Version {policy.version!r}",
                    "use 2012-10-17")
        )
    findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.statement, item.code))
    risk = sum(item.points for item in findings)
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for item in findings:
        counts[item.severity] += 1
    return Review(findings=tuple(findings), risk=risk, grade=_grade(risk), counts=counts)


def _grade(risk: int) -> str:
    if risk == 0:
        return "A"
    if risk <= 10:
        return "B"
    if risk <= 30:
        return "C"
    if risk <= 60:
        return "D"
    return "F"


def _review_statement(statement: Statement) -> list[Finding]:
    findings: list[Finding] = []
    wildcard_action = "*" in statement.actions
    wildcard_resource = "*" in statement.resources or "*" in statement.not_resources

    if statement.effect == "Allow" and wildcard_action and wildcard_resource:
        findings.append(
            Finding(
                "full-admin",
                "critical",
                statement.index,
                "Allow * on * grants full administrator access",
                "list the actions and resources the workload actually needs",
            )
        )
    elif statement.effect == "Allow" and any(
        pattern.endswith(":*") for pattern in statement.actions
    ) and "*" in statement.resources:
        service = next(
            pattern.split(":")[0] for pattern in statement.actions if pattern.endswith(":*")
        )
        findings.append(
            Finding(
                "service-wildcard",
                "high",
                statement.index,
                f"Allow {service}:* on every resource",
                "enumerate the operations; wildcard services grow new actions over time",
            )
        )

    if statement.not_actions:
        findings.append(
            Finding(
                "not-action",
                "high",
                statement.index,
                f"NotAction allows everything except {', '.join(statement.not_actions)}",
                "invert the logic: list the actions to allow",
            )
        )
    if statement.not_resources and statement.effect == "Allow":
        findings.append(
            Finding(
                "not-resource",
                "medium",
                statement.index,
                "NotResource allows the action on every resource that is not listed",
                "use an explicit resource list",
            )
        )

    for action in statement.actions:
        if statement.effect != "Allow" or wildcard_action:
            # A full wildcard is already reported as full-admin; listing every escalation
            # primitive it happens to cover would bury the finding that matters.
            continue
        for risky in ESCALATION_ACTIONS:
            if glob_match(action, risky) and "*" in statement.resources:
                findings.append(
                    Finding(
                        "escalation-primitive",
                        "critical",
                        statement.index,
                        f"{action} on * is a known privilege-escalation path",
                        "scope the resource to the exact role or policy ARN",
                    )
                )
                break

    if statement.effect == "Allow" and not statement.conditions and wildcard_resource:
        findings.append(
            Finding(
                "unconditional-wildcard-resource",
                "medium",
                statement.index,
                "Allow on * with no condition",
                "add a condition such as aws:SourceAccount or aws:PrincipalOrgID",
            )
        )

    if statement.effect == "Allow" and _touches_sensitive_service(statement) and not (
        statement.conditions
    ):
        findings.append(
            Finding(
                "sensitive-without-condition",
                "low",
                statement.index,
                "sensitive service allowed without a condition",
                "consider aws:MultiFactorAuthPresent or a network condition",
            )
        )
    return findings


def _touches_sensitive_service(statement: Statement) -> bool:
    for pattern in statement.actions:
        service = pattern.split(":")[0]
        if service in SENSITIVE_SERVICES:
            return True
    return False
