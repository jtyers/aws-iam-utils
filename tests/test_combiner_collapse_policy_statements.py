from .context import aws_iam_utils

from aws_iam_utils.util import create_policy
from aws_iam_utils.util import create_lowercase_policy
from aws_iam_utils.util import statement

def s3_arn(b):
    return f"arn:aws:s3:::{b}"

def test_collapse_policy_actions():
    p = create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*"),
        statement(actions=[ "s3:GetObject", ], resource="*"),
    )

    assert aws_iam_utils.combiner.collapse_policy_statements(p) == create_lowercase_policy({
        "Effect": "Allow",
        "Action": [
          "s3:putobject",
          "s3:getobject",
        ],
        "Resource": "*",
    })


def test_collapse_policy_action_lists():
    p = create_policy(
        statement(actions=[ "s3:PutObject", "s3:PutBucketPolicy" ], resource="*"),
        statement(actions=[ "s3:GetObject", "s3:GetObjectAcl", "s3:ListBucket" ], resource="*"),
    )

    assert aws_iam_utils.combiner.collapse_policy_statements(p) == create_lowercase_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutBucketPolicy",
            "s3:GetObject",
            "s3:GetObjectAcl",
            "s3:ListBucket",
        ],
        "Resource": "*",
    })


def test_collapse_policy_action_lists_in_multiple_policies():
    pp = [
        create_policy(
            statement(actions=[ "s3:PutObject", "s3:PutBucketPolicy" ], resource="*"),
            statement(actions=[ "s3:GetObject", "s3:GetObjectAcl", "s3:ListBucket" ], resource="*"),
        ),
        create_policy(
            statement(actions=[ "s3:PutObjectVersion", "s3:PutObjectLock" ], resource="*"),
        ),
        create_policy(
            statement(actions=[ "s3:PutLegalHold", "s3:PutObjectAcl" ], resource="*"),
            statement(actions=[ "s3:ListAllMyBuckets", "s3:GetBucketTagging" ], resource="*"),
        ),
    ]

    assert aws_iam_utils.combiner.collapse_policy_statements(*pp) == create_lowercase_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutBucketPolicy",
            "s3:GetObject",
            "s3:GetObjectAcl",
            "s3:ListBucket",
            "s3:PutObjectVersion",
            "s3:PutObjectLock",
            "s3:PutLegalHold",
            "s3:PutObjectAcl",
            "s3:ListAllMyBuckets",
            "s3:GetBucketTagging",
        ],
        "Resource": "*",
    })

def test_collapse_policy_action_lists_in_multiple_policies_with_duplicates():
    pp = [
        create_policy(
            statement(actions=[ "s3:PutObject", "s3:PutBucketPolicy" ], resource="*"),
            statement(actions=[ "s3:GetObject", "s3:GetObjectAcl", "s3:ListBucket" ], resource="*"),
        ),
        create_policy(
            statement(actions=[ "s3:PutObjectVersion", "s3:PutObjectLock" ], resource="*"),
            statement(actions=[ "s3:PutObject", "s3:GetObjectAcl" ], resource="*"),
        ),
        create_policy(
            statement(actions=[ "s3:PutLegalHold", "s3:PutObjectAcl" ], resource="*"),
            statement(actions=[ "s3:ListAllMyBuckets", "s3:GetBucketTagging", "s3:PutObject" ], resource="*"),
        ),
    ]

    assert aws_iam_utils.combiner.collapse_policy_statements(*pp) == create_lowercase_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutBucketPolicy",
            "s3:GetObject",
            "s3:GetObjectAcl",
            "s3:ListBucket",
            "s3:PutObjectVersion",
            "s3:PutObjectLock",
            "s3:PutLegalHold",
            "s3:PutObjectAcl",
            "s3:ListAllMyBuckets",
            "s3:GetBucketTagging",
        ],
        "Resource": "*",
    })



def test_collapse_policy_actions_across_resources():
    p = create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*"),
        statement(actions=[ "s3:GetObject", ], resource="*"),
        statement(actions=[ "s3:PutObjectVersion", ], resource=s3_arn("b1")),
        statement(actions=[ "s3:ListBucket", ], resource=s3_arn("b1")),
    )

    assert aws_iam_utils.combiner.collapse_policy_statements(p) == create_lowercase_policy(
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobject",
                "s3:getobject",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobjectversion",
                "s3:listbucket",
            ],
            "Resource": s3_arn("b1"),
        },
    )


def test_collapse_policy_actions_across_conditions_and_resources():
    p = create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*", condition={'StringEquals': {'foo': 'bar'}}),
        statement(actions=[ "s3:GetObject", ], resource="*"),
        statement(actions=[ "s3:PutObjectVersion", ], resource=s3_arn("b1")),
        statement(actions=[ "s3:ListBucket", ], resource=s3_arn("b1")),
    )

    assert aws_iam_utils.combiner.collapse_policy_statements(p) == create_lowercase_policy(
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobject",
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "foo": "bar"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:getobject",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobjectversion",
                "s3:listbucket",
            ],
            "Resource": s3_arn("b1"),
        },
    )


def test_collapse_policy_actions_across_principals():
    p = create_policy(
        statement(actions="s3:PutObject", principal={"AWS": "foo"}),
        statement(actions="s3:PutObjectVersion", principal={"AWS": "bar"}),
        statement(actions="s3:GetObject", principal={"AWS": "foo"}),
        statement(actions="s3:ListBucket", principal={"AWS": "bar"}),
    )

    assert aws_iam_utils.combiner.collapse_policy_statements(p) == create_lowercase_policy(
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobject",
                "s3:getobject",
            ],
            "Principal": {
                "AWS": "foo"
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobjectversion",
                "s3:listbucket",
            ],
            "Principal": {
                "AWS": "bar"
            }
        },
    )


def test_collapse_policy_actions_across_principals_and_effects():
    p = create_policy(
        statement(actions="s3:PutObject", principal={"AWS": "foo"}),
        statement(actions="s3:PutObjectVersion", principal={"AWS": "bar"}),
        statement(actions="s3:GetObject", principal={"AWS": "foo"}),
        statement(actions="s3:ListBucket", principal={"AWS": "bar"}),
        statement(actions="s3:GetObject", principal={"AWS": "foo"}, effect="Deny"),
        statement(actions="s3:ListBucket", principal={"AWS": "foo"}, effect="Deny"),
    )

    assert aws_iam_utils.combiner.collapse_policy_statements(p) == create_lowercase_policy(
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobject",
                "s3:getobject",
            ],
            "Principal": {
                "AWS": "foo"
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:putobjectversion",
                "s3:listbucket",
            ],
            "Principal": {
                "AWS": "bar"
            }
        },
        {
            "Effect": "Deny",
            "Action": [
                "s3:getobject",
                "s3:listbucket",
            ],
            "Principal": {
                "AWS": "foo"
            }
        },
    )


