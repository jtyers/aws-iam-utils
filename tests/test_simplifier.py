import pytest
import copy

from .context import aws_iam_utils
from aws_iam_utils.util import create_policy
from aws_iam_utils.util import statement
from aws_iam_utils.simplifier import simplify_policy

def test_simplify_policy():
    p = create_policy(
        statement(actions=["s3:*"], resource=["foo"], principal={"AWS":["bar"]}),
    )

    assert simplify_policy(p) == create_policy(
        statement(actions="s3:*", resource="foo", principal={"AWS":"bar"}),
    )

def test_simplify_policy_service_principal():
    p = create_policy(
        statement(actions=["s3:*"], resource=["foo"], principal={"Service":["bar"]}),
    )

    assert simplify_policy(p) == create_policy(
        statement(actions="s3:*", resource="foo", principal={"Service":"bar"}),
    )

def test_simplify_policy_skip_multiple_actions():
    p = create_policy(
        statement(actions=["s3:*", "lambda:*"], resource=["foo"], principal={"Service":["bar"]}),
    )

    assert simplify_policy(p) == create_policy(
        statement(actions=["s3:*", "lambda:*"], resource="foo", principal={"Service":"bar"}),
    )

def test_simplify_policy_skip_multiple_resources():
    p = create_policy(
        statement(actions=["s3:*"], resource=["foo", "bar"], principal={"Service":["bar"]}),
    )

    assert simplify_policy(p) == create_policy(
        statement(actions="s3:*", resource=["foo", "bar"], principal={"Service":"bar"}),
    )

def test_simplify_policy_skip_multiple_aws_principals():
    p = create_policy(
        statement(actions=["s3:*"], resource=["foo"], principal={"AWS":["bar", "baz"]}),
    )

    assert simplify_policy(p) == create_policy(
        statement(actions="s3:*", resource="foo", principal={"AWS":["bar", "baz"]}),
    )

def test_simplify_policy_skip_multiple_service_principals():
    p = create_policy(
        statement(actions=["s3:*"], resource=["foo"], principal={"Service":["bar", "baz"]}),
    )

    assert simplify_policy(p) == create_policy(
        statement(actions="s3:*", resource="foo", principal={"Service":["bar", "baz"]}),
    )
