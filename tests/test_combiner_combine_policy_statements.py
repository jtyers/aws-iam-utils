from .context import aws_iam_utils

from aws_iam_utils.util import create_policy
from aws_iam_utils.util import statement

from .testutil import create_lowercase_policy

def s3_arn(b):
    return f"arn:aws:s3:::{b}"

def test_combine_nothing_should_return_empty_policy():
    assert aws_iam_utils.combiner.combine_policy_statements() == create_policy()

def test_combine_empty_policy_should_return_empty_policy_with_same_version():
    p = create_policy(version="2008-01-01")

    assert aws_iam_utils.combiner.combine_policy_statements(p) == create_policy(version="2008-01-01")

def test_combine_single_policy_should_be_same_result():
    p = create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*"),
        statement(actions=[ "s3:GetObject", ], resource="*"),
    )

    assert aws_iam_utils.combiner.combine_policy_statements(p) == create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*"),
        statement(actions=[ "s3:GetObject", ], resource="*"),
    )

def test_combine_two_simple_policies():
    p = create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*"),
        statement(actions=[ "s3:GetObject", ], resource="*"),
    )

    p2 = create_policy(
        statement(actions=[ "s3:PutObject", "s3:ListBucket" ], resource="foo"),
    )

    assert aws_iam_utils.combiner.combine_policy_statements(p, p2) == create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*"),
        statement(actions=[ "s3:GetObject", ], resource="*"),
        statement(actions=[ "s3:PutObject", "s3:ListBucket" ], resource="foo"),
    )

def test_combine_many_policies_with_various_keys():
    pp = [
        create_policy(
            statement(actions=[ "s3:PutObject", ], resource="*"),
            statement(actions=[ "s3:GetObject", ], resource="*"),
        ),
        create_policy(
            statement(actions=[ "s3:PutObject", "s3:ListBucket" ], resource="foo"),
        ),
        create_policy(
            statement(actions=[ "s3:GetObjectVersion", "s3:GetObjectAcl" ], resource="bar", condition={"StringEquals":{"foo":"bar"}}),
        ),
        create_policy(
            statement(actions="s3:GetObjectLock", principal={"Service":"dotdot"}),
        ),
        create_policy(
            statement(effect="Deny", actions="s3:PutBucketPolicy", principal={"Service":"ec2"}, resource=["bat", "baz"]),
            statement(effect="Deny", actions="s3:PutBucketPolicy", condition={"StringNotEquals":{"service":"ec2"}}, resource=["bat", "baz"]),
        ),
    ]

    assert aws_iam_utils.combiner.combine_policy_statements(*pp) == create_policy(
        statement(actions=[ "s3:PutObject", ], resource="*"),
        statement(actions=[ "s3:GetObject", ], resource="*"),
        statement(actions=[ "s3:PutObject", "s3:ListBucket" ], resource="foo"),
        statement(actions=[ "s3:GetObjectVersion", "s3:GetObjectAcl" ], resource="bar", condition={"StringEquals":{"foo":"bar"}}),
        statement(actions="s3:GetObjectLock", principal={"Service":"dotdot"}),
        statement(effect="Deny", actions="s3:PutBucketPolicy", principal={"Service":"ec2"}, resource=["bat", "baz"]),
        statement(effect="Deny", actions="s3:PutBucketPolicy", condition={"StringNotEquals":{"service":"ec2"}}, resource=["bat", "baz"]),
    )
