"""Command line entry point for ``iam-analyze``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .evaluate import EvaluateError, Request, evaluate
from .policy import Policy, PolicyError, load_policy
from .report import (
    render_batch,
    render_decision,
    render_markdown,
    render_matrix,
    render_review,
    render_review_json,
)
from .review import review

SEVERITIES = ("low", "medium", "high", "critical")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-analyze",
        description="Evaluate IAM policies and review them for risky grants.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="evaluate one request")
    check.add_argument("--policy", required=True)
    check.add_argument("--action", required=True)
    check.add_argument("--resource", required=True)
    check.add_argument("--context", action="append", default=[],
                       help="key=value, repeatable")
    check.add_argument("--format", choices=("text", "json"), default="text")

    batch = sub.add_parser("batch", help="check a JSONL list of requests")
    batch.add_argument("--policy", required=True)
    batch.add_argument("--requests", required=True)
    batch.add_argument("--format", choices=("text", "json"), default="text")

    rev = sub.add_parser("review", help="score a policy document")
    rev.add_argument("--policy", required=True)
    rev.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    rev.add_argument("--fail-on", choices=("never",) + SEVERITIES, default="high")

    matrix = sub.add_parser("matrix", help="decision grid for actions x resources")
    matrix.add_argument("--policy", required=True)
    matrix.add_argument("--actions", required=True)
    matrix.add_argument("--resources", required=True)

    statements = sub.add_parser("statements", help="list statements in a readable form")
    statements.add_argument("--policy", required=True)

    validate = sub.add_parser("validate", help="parse and validate a policy")
    validate.add_argument("--policy", required=True)
    return parser


def _load(path: str) -> Policy | None:
    try:
        return load_policy(path)
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return None


def _context(pairs: list[str]) -> dict[str, str]:
    context: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise EvaluateError(f"context must be key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        context[key] = value
    return context


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    policy = _load(args.policy)
    if policy is None:
        return 2

    if args.command == "validate":
        print(f"policy ok: {args.policy}")
        print(f"  version    {policy.version}")
        print(f"  statements {len(policy.statements)}")
        for statement in policy.statements:
            print(f"  {statement.label}")
        return 0

    if args.command == "statements":
        for statement in policy.statements:
            actions = ", ".join(statement.actions or [f"NOT {a}" for a in statement.not_actions])
            resources = ", ".join(statement.resources or
                                  [f"NOT {r}" for r in statement.not_resources])
            print(f"{statement.index}. {statement.effect:<6} {actions}")
            print(f"   resources: {resources}")
            for operator, entries in statement.conditions.items():
                for key, values in entries.items():
                    print(f"   if {operator} {key} = {', '.join(values)}")
        return 0

    if args.command == "check":
        try:
            request = Request(args.action, args.resource, _context(args.context))
        except EvaluateError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        decision = evaluate(policy, request)
        if args.format == "json":
            print(json.dumps({"request": request.as_dict(), **decision.as_dict()}, indent=2))
        else:
            print(render_decision(decision, request_label=request.label))
        return 0 if decision.allowed else 1

    if args.command == "batch":
        rows, error = _run_batch(policy, args.requests)
        if error is not None:
            print(f"requests error: {error}", file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        else:
            print(render_batch(rows))
        return 1 if any(row.get("expect") and row["effect"] != row["expect"] for row in rows) else 0

    if args.command == "review":
        result = review(policy)
        if args.format == "json":
            print(render_review_json(result))
        elif args.format == "markdown":
            print(render_markdown(result))
        else:
            print(render_review(result, title=f"Policy review: {args.policy}"))
        return 1 if result.should_fail(args.fail_on) else 0

    if args.command == "matrix":
        actions = [part.strip() for part in args.actions.split(",") if part.strip()]
        resources = [part.strip() for part in args.resources.split(",") if part.strip()]
        if not actions or not resources:
            print("error: --actions and --resources must not be empty", file=sys.stderr)
            return 2
        grid = [
            [evaluate(policy, Request(action, resource)) for resource in resources]
            for action in actions
        ]
        print(render_matrix(actions, resources, grid))
        return 0

    return 2


def _run_batch(policy: Policy, path: str) -> tuple[list[dict], str | None]:
    source = Path(path)
    if not source.exists():
        return [], f"file not found: {source}"
    rows: list[dict] = []
    for line_number, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            return [], f"line {line_number}: not valid JSON ({exc.msg})"
        if not isinstance(data, dict) or "action" not in data or "resource" not in data:
            return [], f"line {line_number}: needs action and resource"
        try:
            request = Request(str(data["action"]), str(data["resource"]),
                              {str(k): str(v) for k, v in (data.get("context") or {}).items()})
        except EvaluateError as exc:
            return [], f"line {line_number}: {exc}"
        expect = data.get("expect")
        if expect not in (None, "Allow", "Deny"):
            return [], f"line {line_number}: expect must be Allow or Deny"
        decision = evaluate(policy, request)
        rows.append({"request": request.as_dict(), "expect": expect, **decision.as_dict()})
    if not rows:
        return [], "no requests found"
    return rows, None
