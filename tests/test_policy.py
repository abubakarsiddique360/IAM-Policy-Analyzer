import json

import pytest

from iam_policy_analyzer.policy import (
    Policy,
    PolicyError,
    glob_match,
    load_policy,
    parse_policy,
)

MINIMAL = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::bucket/*",
    },
}


def write(tmp_path, data, name="policy.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "pattern,value,expected",
    [
        ("*", "s3:GetObject", True),
        ("s3:*", "s3:GetObject", True),
        ("s3:Get*", "s3:GetObject", True),
        ("s3:Get*", "s3:PutObject", False),
        ("s3:GetObjec?", "s3:GetObject", True),
        ("arn:aws:s3:::b/*", "arn:aws:s3:::b/key", True),
        ("arn:aws:s3:::b/*", "arn:aws:s3:::c/key", False),
        ("a.b", "axb", False),
    ],
)
def test_glob_match(pattern, value, expected):
    assert glob_match(pattern, value) is expected


def test_single_statement_object_is_accepted():
    policy = parse_policy(MINIMAL)
    assert len(policy.statements) == 1
    statement = policy.statements[0]
    assert statement.effect == "Allow"
    assert statement.actions == ("s3:GetObject",)
    assert statement.label == "statement 1 (Allow s3:GetObject)"


def test_lists_and_conditions_are_parsed():
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt", "kms:Encrypt"],
                    "Resource": "arn:aws:kms:eu-west-1:111122223333:key/k",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                }
            ],
        }
    )
    statement = policy.statements[0]
    assert statement.conditions == {"StringEquals": {"aws:PrincipalOrgID": ("o-abc",)}}
    assert statement.as_dict() if hasattr(statement, "as_dict") else True


@pytest.mark.parametrize(
    "data,message",
    [
        ("nope", "JSON object"),
        ({"Version": "2012-10-17"}, "Statement"),
        ({"Statement": []}, "non-empty"),
        ({"Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]}, "Effect"),
        ({"Statement": [{"Effect": "Allow", "Resource": "*"}]}, "Action or NotAction"),
        (
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*", "NotResource": "*"}
                ]
            },
            "Resource or NotResource",
        ),
        (
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Extra": 1}]},
            "unknown field",
        ),
        (
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {"StringEqualsIfExists": {"a": "b"}},
                    }
                ]
            },
            "unsupported condition operator",
        ),
        (
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*",
                     "Condition": {"StringEquals": {}}}
                ]
            },
            "non-empty object",
        ),
    ],
)
def test_parse_errors(data, message):
    with pytest.raises(PolicyError, match=message):
        parse_policy(data)


def test_unknown_top_level_field_is_rejected():
    with pytest.raises(PolicyError, match="unknown policy field"):
        parse_policy(dict(MINIMAL, Comment="hello"))


def test_load_policy_from_file(tmp_path):
    policy = load_policy(write(tmp_path, MINIMAL))
    assert policy.source.endswith("policy.json")
    assert policy.version == "2012-10-17"


def test_load_policy_errors(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "absent.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid JSON"):
        load_policy(broken)


def test_policy_serialises():
    payload = parse_policy(MINIMAL).as_dict()
    assert payload["statements"][0]["effect"] == "Allow"
    assert payload["statements"][0]["actions"] == ["s3:GetObject"]


def test_not_action_and_not_resource_are_kept():
    policy = parse_policy(
        {
            "Statement": [
                {"Effect": "Allow", "NotAction": "iam:*", "NotResource": "arn:aws:s3:::b/*"}
            ]
        }
    )
    statement = policy.statements[0]
    assert statement.not_actions == ("iam:*",)
    assert statement.not_resources == ("arn:aws:s3:::b/*",)
    assert isinstance(policy, Policy)
