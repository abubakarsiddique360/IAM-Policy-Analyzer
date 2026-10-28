"""Policy documents: parse, validate and check whether a statement matches a request.

Statements follow the IAM shape closely enough to be recognisable - ``Effect``,
``Action``/``NotAction``, ``Resource``/``NotResource`` and ``Condition`` - while staying
strict about what it accepts. A policy that silently ignores a field it does not understand is
worse than one that refuses to load.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EFFECTS = ("Allow", "Deny")

# Condition operators this evaluator understands. Anything else is rejected at load time
# rather than quietly treated as "true".
CONDITION_OPERATORS = (
    "StringEquals",
    "StringNotEquals",
    "StringLike",
    "StringNotLike",
    "ArnLike",
    "ArnNotLike",
    "Bool",
    "NumericLessThan",
    "NumericGreaterThan",
    "IpAddress",
    "NotIpAddress",
)


class PolicyError(ValueError):
    """Raised when a policy document cannot be used."""


def _as_list(value: Any, label: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise PolicyError(f"{label} must be a string or a list of strings")


def _glob_to_regex(pattern: str) -> str:
    """IAM wildcards: ``*`` is any run of characters, ``?`` is exactly one."""
    out: list[str] = []
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(_escape(char))
    return "".join(out)


def _escape(char: str) -> str:
    return "\\" + char if char in r".^$+{}[]|()\\" else char


def glob_match(pattern: str, value: str) -> bool:
    """Case-sensitive match of an IAM wildcard pattern against a value."""
    import re

    return re.fullmatch(_glob_to_regex(pattern), value) is not None


@dataclass(frozen=True)
class Statement:
    index: int
    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    conditions: dict[str, dict[str, tuple[str, ...]]] = field(default_factory=dict)

    @property
    def label(self) -> str:
        first = self.actions[0] if self.actions else (
            f"NOT {self.not_actions[0]}" if self.not_actions else "*"
        )
        return f"statement {self.index} ({self.effect} {first})"

    def matches_action(self, action: str) -> bool:
        if self.actions:
            return any(glob_match(pattern, action) for pattern in self.actions)
        if self.not_actions:
            return not any(glob_match(pattern, action) for pattern in self.not_actions)
        return True

    def matches_resource(self, resource: str) -> bool:
        if self.resources:
            return any(glob_match(pattern, resource) for pattern in self.resources)
        if self.not_resources:
            return not any(glob_match(pattern, resource) for pattern in self.not_resources)
        return True


@dataclass(frozen=True)
class Policy:
    version: str
    statements: tuple[Statement, ...]
    source: str = "<memory>"

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "source": self.source,
            "statements": [
                {
                    "index": statement.index,
                    "effect": statement.effect,
                    "actions": list(statement.actions or statement.not_actions),
                    "resources": list(statement.resources or statement.not_resources),
                    "conditions": {
                        operator: {key: list(values) for key, values in entries.items()}
                        for operator, entries in statement.conditions.items()
                    },
                }
                for statement in self.statements
            ],
        }


def load_policy(path: str | Path) -> Policy:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy not found: {source}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from exc
    policy = parse_policy(data)
    return Policy(version=policy.version, statements=policy.statements, source=str(source))


def parse_policy(data: Any) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    allowed = {"Version", "Statement", "Id"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyError(f"unknown policy field(s): {', '.join(unknown)}")
    version = str(data.get("Version", "2012-10-17"))
    raw_statements = data.get("Statement")
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list) or not raw_statements:
        raise PolicyError("Statement must be a non-empty object or list")
    statements = tuple(
        _parse_statement(raw, index)
        for index, raw in enumerate(raw_statements, start=1)
    )
    return Policy(version=version, statements=statements)


def _parse_statement(raw: Any, index: int) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyError(f"statement {index} must be an object")
    allowed = {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyError(f"statement {index}: unknown field(s): {', '.join(unknown)}")
    effect = raw.get("Effect")
    if effect not in EFFECTS:
        raise PolicyError(f"statement {index}: Effect must be Allow or Deny")
    if ("Action" in raw) == ("NotAction" in raw):
        raise PolicyError(f"statement {index}: needs exactly one of Action or NotAction")
    if ("Resource" in raw) == ("NotResource" in raw):
        raise PolicyError(f"statement {index}: needs exactly one of Resource or NotResource")

    actions = tuple(_as_list(raw["Action"], f"statement {index} Action")) if "Action" in raw else ()
    not_actions = (
        tuple(_as_list(raw["NotAction"], f"statement {index} NotAction"))
        if "NotAction" in raw
        else ()
    )
    resources = (
        tuple(_as_list(raw["Resource"], f"statement {index} Resource"))
        if "Resource" in raw
        else ()
    )
    not_resources = (
        tuple(_as_list(raw["NotResource"], f"statement {index} NotResource"))
        if "NotResource" in raw
        else ()
    )
    conditions = _parse_conditions(raw.get("Condition", {}), index)
    return Statement(
        index=index,
        effect=str(effect),
        actions=actions,
        not_actions=not_actions,
        resources=resources,
        not_resources=not_resources,
        conditions=conditions,
    )


def _parse_conditions(raw: Any, index: int) -> dict[str, dict[str, tuple[str, ...]]]:
    if raw in ({}, None):
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(f"statement {index}: Condition must be an object")
    conditions: dict[str, dict[str, tuple[str, ...]]] = {}
    for operator, entries in raw.items():
        if operator not in CONDITION_OPERATORS:
            raise PolicyError(
                f"statement {index}: unsupported condition operator {operator!r}; supported: "
                + ", ".join(CONDITION_OPERATORS)
            )
        if not isinstance(entries, dict) or not entries:
            raise PolicyError(f"statement {index}: condition {operator} must be a non-empty object")
        conditions[operator] = {
            str(key): tuple(_as_list(value, f"statement {index} condition {key}"))
            for key, value in entries.items()
        }
    return conditions
