import pytest

from iam_policy_analyzer.evaluate import EvaluateError, Request, evaluate
from iam_policy_analyzer.policy import parse_policy
from iam_policy_analyzer.review import review

BASE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"},
        {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": "arn:aws:s3:::b/locked/*"},
    ],
}


def policy(statements):
    return parse_policy({"Version": "2012-10-17", "Statement": statements})


def allow(action="s3:GetObject", resource="arn:aws:s3:::b/key", context=None):
    return evaluate(parse_policy(BASE), Request(action, resource, context or {}))


def test_allow_when_a_statement_matches():
    decision = allow()
    assert decision.allowed
    assert decision.effect == "Allow"
    assert decision.reason == "allowed by statement 1"


def test_explicit_deny_beats_allow():
    decision = allow("s3:DeleteObject", "arn:aws:s3:::b/locked/key")
    assert decision.effect == "Deny"
    assert "explicit deny" in decision.reason
    assert decision.decided_by in (2,)


def test_default_is_deny():
    decision = allow("ec2:RunInstances", "arn:aws:ec2:eu-west-1:1:instance/i-1")
    assert decision.effect == "Deny"
    assert "default is deny" in decision.reason
    assert decision.matched_allows == ()
    assert decision.matched_denies == ()


def test_wildcards_in_action_and_resource():
    document = policy([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
    decision = evaluate(document, Request("s3:PutBucketPolicy", "arn:aws:s3:::anything"))
    assert decision.allowed


def test_not_action_allows_everything_else():
    document = policy([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
    assert evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b")).allowed
    assert not evaluate(document, Request("iam:CreateUser", "arn:aws:iam::1:user/x")).allowed


def test_not_resource_excludes_listed_resources():
    document = policy([{"Effect": "Allow", "Action": "s3:*", "NotResource": "arn:aws:s3:::b/*"}])
    assert evaluate(document, Request("s3:GetObject", "arn:aws:s3:::c/key")).allowed
    assert not evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b/key")).allowed


def test_ip_condition_gates_the_allow():
    document = policy(
        [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "arn:aws:kms:eu-west-1:1:key/k",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }
        ]
    )
    inside = evaluate(
        document,
        Request("kms:Decrypt", "arn:aws:kms:eu-west-1:1:key/k", {"aws:SourceIp": "203.0.113.9"}),
    )
    outside = evaluate(
        document,
        Request("kms:Decrypt", "arn:aws:kms:eu-west-1:1:key/k", {"aws:SourceIp": "198.51.100.1"}),
    )
    missing = evaluate(document, Request("kms:Decrypt", "arn:aws:kms:eu-west-1:1:key/k"))
    assert inside.allowed
    assert not outside.allowed
    assert not missing.allowed


def test_not_ip_and_negated_string_conditions():
    document = policy(
        [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"},
                    "StringNotEquals": {"aws:PrincipalTag/team": "red"},
                },
            }
        ]
    )
    context = {"aws:SourceIp": "198.51.100.3", "aws:PrincipalTag/team": "blue"}
    assert evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b", context)).allowed
    red = {"aws:SourceIp": "198.51.100.3", "aws:PrincipalTag/team": "red"}
    assert not evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b", red)).allowed
    internal = {"aws:SourceIp": "10.1.2.3", "aws:PrincipalTag/team": "blue"}
    assert not evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b", internal)).allowed


def test_negated_condition_is_satisfied_by_a_missing_key():
    document = policy(
        [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:PrincipalTag/team": "red"}},
            }
        ]
    )
    assert evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b")).allowed


def test_numeric_and_bool_conditions():
    document = policy(
        [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "Bool": {"aws:SecureTransport": "true"},
                    "NumericLessThan": {"s3:max-keys": "100"},
                },
            }
        ]
    )
    good = {"aws:SecureTransport": "true", "s3:max-keys": "50"}
    bad = {"aws:SecureTransport": "false", "s3:max-keys": "50"}
    too_big = {"aws:SecureTransport": "true", "s3:max-keys": "500"}
    assert evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b", good)).allowed
    assert not evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b", bad)).allowed
    assert not evaluate(document, Request("s3:GetObject", "arn:aws:s3:::b", too_big)).allowed


def test_request_validation():
    with pytest.raises(EvaluateError, match="service:Operation"):
        Request("GetObject", "arn")
    with pytest.raises(EvaluateError, match="resource"):
        Request("s3:GetObject", "")


def test_decision_serialises_and_names_the_deciding_statement():
    decision = allow("s3:DeleteObject", "arn:aws:s3:::b/locked/key")
    payload = decision.as_dict()
    assert payload["effect"] == "Deny"
    assert payload["decided_by"] == 2
    assert payload["matched_denies"] == [2]


def test_review_flags_full_admin_as_critical():
    result = review(policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
    codes = {finding.code for finding in result.findings}
    assert "full-admin" in codes
    assert result.counts["critical"] >= 1
    assert result.should_fail("critical")
    assert not result.should_fail("never")


def test_review_flags_service_wildcard_and_not_action():
    result = review(policy([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]))
    assert any(finding.code == "service-wildcard" for finding in result.findings)
    second = review(policy([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]))
    assert any(finding.code == "not-action" for finding in second.findings)


def test_review_flags_escalation_primitive():
    result = review(
        policy([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}])
    )
    assert any(finding.code == "escalation-primitive" for finding in result.findings)


def test_review_is_quiet_for_a_scoped_conditional_policy():
    result = review(
        policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::b/*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                }
            ]
        )
    )
    assert result.clean
    assert result.risk == 0
    assert result.grade == "A"


def test_review_flags_a_missing_condition_on_kms():
    result = review(
        policy([{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "arn:aws:kms:1:key/k"}])
    )
    assert any(finding.code == "sensitive-without-condition" for finding in result.findings)


def test_review_grade_bands():
    clean = review(policy([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"}]))
    assert clean.grade == "A"
    bad = review(policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
    assert bad.grade in ("D", "F")
    assert bad.risk >= 30


def test_review_findings_are_ordered_by_severity():
    result = review(
        policy(
            [
                {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "arn:k"},
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ]
        )
    )
    severities = [finding.severity for finding in result.findings]
    assert severities[0] == "critical"
    assert severities == sorted(
        severities, key=lambda severity: {"critical": 0, "high": 1, "medium": 2, "low": 3}[severity]
    )
