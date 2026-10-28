import json

import pytest

from iam_policy_analyzer.cli import main
from iam_policy_analyzer.evaluate import Request, evaluate
from iam_policy_analyzer.policy import parse_policy
from iam_policy_analyzer.report import (
    render_batch,
    render_decision,
    render_markdown,
    render_matrix,
    render_review,
    render_review_json,
)
from iam_policy_analyzer.review import review

DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::b/locked/*"},
    ],
}


@pytest.fixture()
def policy_file(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
    return path


def test_decision_report_names_statements():
    policy = parse_policy(DOCUMENT)
    decision = evaluate(policy, Request("s3:DeleteObject", "arn:aws:s3:::b/locked/key"))
    text = render_decision(decision, request_label="s3:DeleteObject")
    assert "effect      Deny" in text
    assert "Matched statements" in text
    assert "statement 3 (Deny s3:DeleteObject)" in text


def test_review_report_shows_severities_and_fixes():
    result = review(parse_policy(DOCUMENT))
    text = render_review(result)
    assert "CRITICAL" in text
    assert "fix:" in text
    assert "risk" in text


def test_clean_review_says_so():
    result = review(parse_policy(
        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"}]}
    ))
    assert "No findings" in render_review(result)


def test_markdown_and_json_review():
    result = review(parse_policy(DOCUMENT))
    markdown = render_markdown(result)
    assert "| Severity | Statement | Finding | Fix |" in markdown
    payload = json.loads(render_review_json(result))
    assert payload["grade"] in ("D", "F")
    assert payload["findings"]


def test_batch_report_counts_mismatches():
    rows = [
        {"request": {"action": "s3:GetObject", "resource": "arn:aws:s3:::b/k"},
         "expect": "Allow", "effect": "Allow"},
        {"request": {"action": "ec2:Run", "resource": "arn:aws:ec2:1:i"},
         "expect": "Allow", "effect": "Deny"},
    ]
    text = render_batch(rows)
    assert "PASS" in text
    assert "FAIL" in text
    assert "mismatches 1" in text


def test_matrix_report():
    policy = parse_policy(DOCUMENT)
    actions = ["s3:GetObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::b/k", "arn:aws:s3:::b/locked/k"]
    grid = [[evaluate(policy, Request(a, r)) for r in resources] for a in actions]
    text = render_matrix(actions, resources, grid)
    assert "Decision matrix" in text
    assert "Allow" in text and "Deny" in text


def test_cli_validate(policy_file, capsys):
    assert main(["validate", "--policy", str(policy_file)]) == 0
    output = capsys.readouterr().out
    assert "policy ok" in output
    assert "statements 3" in output


def test_cli_validate_bad_policy(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    assert main(["validate", "--policy", str(bad)]) == 2
    assert "policy error" in capsys.readouterr().err


def test_cli_statements(policy_file, capsys):
    assert main(["statements", "--policy", str(policy_file)]) == 0
    output = capsys.readouterr().out
    assert "1. Allow" in output
    assert "resources:" in output


def test_cli_check_exit_codes(policy_file, capsys):
    assert main(["check", "--policy", str(policy_file), "--action", "s3:GetObject",
                 "--resource", "arn:aws:s3:::b/key"]) == 0
    assert "Allow" in capsys.readouterr().out
    assert main(["check", "--policy", str(policy_file), "--action", "s3:DeleteObject",
                 "--resource", "arn:aws:s3:::b/locked/key"]) == 1
    assert "Deny" in capsys.readouterr().out


def test_cli_check_json_and_context(policy_file, capsys):
    assert main(["check", "--policy", str(policy_file), "--action", "s3:GetObject",
                 "--resource", "arn:aws:s3:::b/key", "--context", "aws:SourceIp=10.0.0.1",
                 "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["request"]["context"]["aws:SourceIp"] == "10.0.0.1"
    assert payload["effect"] == "Allow"


def test_cli_check_rejects_bad_request(policy_file, capsys):
    assert main(["check", "--policy", str(policy_file), "--action", "nope",
                 "--resource", "arn:x"]) == 2
    assert "service:Operation" in capsys.readouterr().err
    assert main(["check", "--policy", str(policy_file), "--action", "s3:GetObject",
                 "--resource", "arn:x", "--context", "novalue"]) == 2
    assert "key=value" in capsys.readouterr().err


def test_cli_batch(policy_file, tmp_path, capsys):
    requests = tmp_path / "requests.jsonl"
    requests.write_text(
        json.dumps({"action": "s3:GetObject", "resource": "arn:aws:s3:::b/k",
                    "expect": "Allow"}) + "\n",
        encoding="utf-8",
    )
    assert main(["batch", "--policy", str(policy_file), "--requests", str(requests)]) == 0
    assert "mismatches 0" in capsys.readouterr().out


def test_cli_batch_reports_mismatch(policy_file, tmp_path, capsys):
    requests = tmp_path / "requests.jsonl"
    requests.write_text(
        json.dumps({"action": "ec2:Run", "resource": "arn:aws:ec2:1:i", "expect": "Deny"})
        + "\n",
        encoding="utf-8",
    )
    assert main(["batch", "--policy", str(policy_file), "--requests", str(requests)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_batch_errors(policy_file, tmp_path, capsys):
    missing = tmp_path / "none.jsonl"
    assert main(["batch", "--policy", str(policy_file), "--requests", str(missing)]) == 2
    broken = tmp_path / "broken.jsonl"
    broken.write_text("{nope}\n", encoding="utf-8")
    assert main(["batch", "--policy", str(policy_file), "--requests", str(broken)]) == 2
    assert "not valid JSON" in capsys.readouterr().err
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n", encoding="utf-8")
    assert main(["batch", "--policy", str(policy_file), "--requests", str(empty)]) == 2
    assert "no requests" in capsys.readouterr().err


def test_cli_review(policy_file, capsys):
    assert main(["review", "--policy", str(policy_file), "--fail-on", "never"]) == 0
    assert "CRITICAL" in capsys.readouterr().out
    assert main(["review", "--policy", str(policy_file)]) == 1


def test_cli_review_markdown_and_json(policy_file, capsys):
    assert main(["review", "--policy", str(policy_file), "--format", "markdown",
                 "--fail-on", "never"]) == 0
    assert "### Policy review" in capsys.readouterr().out
    assert main(["review", "--policy", str(policy_file), "--format", "json",
                 "--fail-on", "never"]) == 0
    assert json.loads(capsys.readouterr().out)["risk"] > 0


def test_cli_matrix(policy_file, capsys):
    assert main(["matrix", "--policy", str(policy_file),
                 "--actions", "s3:GetObject,s3:DeleteObject",
                 "--resources", "arn:aws:s3:::b/k,arn:aws:s3:::b/locked/k"]) == 0
    output = capsys.readouterr().out
    assert "Decision matrix" in output
    assert "Deny" in output


def test_cli_matrix_rejects_empty_lists(policy_file, capsys):
    assert main(["matrix", "--policy", str(policy_file), "--actions", ",",
                 "--resources", "arn:x"]) == 2
    assert "must not be empty" in capsys.readouterr().err
