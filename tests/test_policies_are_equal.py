import pytest
import random
import copy

from policyuniverse.expander_minimizer import minimize_policy
from .context import iam_policy_resolver

def create_policy(*statements):
    return {
        "Version": "2012-10-17",
        "Statement": statements
    }

def reorder_policy(p):
    """Returns a copy of p which has had its Statements and nested Actions re-ordered randomly."""
    result = copy.deepcopy(p)
    random.shuffle(result["Statement"])

    for statement in result["Statement"]:
        if type(statement["Action"]) is list:
            random.shuffle(statement["Action"])

    assert result != p  # assert the order is actually different
    return result

def wildcard_policy(p):
    """Returns a copy of p which has been minimized (i.e. wildcards inserted)."""
    result = copy.deepcopy(p)
    result = minimize_policy(result)

    assert result != p  # assert the order is actually different
    return result

@pytest.fixture
def policy_1():
    return create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutObjectVersionAcl",
            "s3:PutObjectVersionTagging",
            "s3:GetObjectVersion",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionAttributes",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionTorrent",
            "s3:GetObject",
        ],
        "Resource": "*",
    })

@pytest.fixture
def policy_1_reordered(policy_1):
    return reorder_policy(policy_1)


@pytest.fixture
def policy_1_wildcards(policy_1):
    return wildcard_policy(policy_1)

@pytest.fixture
def policy_2():
    return create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutObjectVersionAcl",
            "s3:PutObjectVersionTagging",
        ],
        "Resource": "*",
    },
    {
        "Effect": "Deny",
        "Action": [
            "s3:GetObjectLock",
            "s3:GetBucketPolicy",
            "s3:PutBucketPolicy",
        ],
        "Resource": "*",
    })

@pytest.fixture
def policy_2_reordered(policy_2):
    return reorder_policy(policy_2)

@pytest.fixture
def policy_2_wildcards(policy_2):
    return wildcard_policy(policy_2)

def test_policies_equal_when_inputs_equal(policy_1, policy_1_wildcards):
    assert iam_policy_resolver.policies_are_equal(policy_1, policy_1_wildcards)

def test_policies_equal_when_inputs_equal_but_reordered(policy_1_reordered, policy_1_wildcards):
    assert iam_policy_resolver.policies_are_equal(policy_1_reordered, policy_1_wildcards)

def test_policies_not_equal_when_inputs_differ(policy_1, policy_2):
    assert not iam_policy_resolver.policies_are_equal(policy_1, policy_2)

def test_policies_equal_when_permissions_across_statements():
    p1 = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutObjectVersionAcl",
            "s3:PutObjectVersionTagging",
        ],
        "Resource": "*",
    })

    p2 = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
        ],
        "Resource": "*",
    },{
        "Effect": "Allow",
        "Action": [
            "s3:PutObjectVersionAcl",
            "s3:PutObjectVersionTagging",
        ],
        "Resource": "*",
    })

    assert iam_policy_resolver.policies_are_equal(p1, p2)

def test_policies_not_equal_when_permissions_across_statements_differing_resources():
    p1 = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutObjectVersionAcl",
            "s3:PutObjectVersionTagging",
        ],
        "Resource": "*",
    })

    p2 = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
        ],
        "Resource": "arn:aws:s3:::my-bucket/*",
    },{
        "Effect": "Allow",
        "Action": [
            "s3:PutObjectVersionAcl",
            "s3:PutObjectVersionTagging",
        ],
        "Resource": "*",
    })

    assert not iam_policy_resolver.policies_are_equal(p1, p2)

def test_policies_equal_with_conditions():
    p1 = create_policy({
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "*",
        "Condition": {
            "StringNotEqual": { "foo": "bar" }
        },
    })

    p2 = create_policy({
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "*",
        "Condition": {
            "StringNotEqual": { "foo": "bar" }
        },
    })

    assert iam_policy_resolver.policies_are_equal(p1, p2)

def test_policies_not_equal_with_conditions_differing():
    p1 = create_policy({
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "*",
        "Condition": {
            "StringNotEqual": { "foo": "bar" }
        },
    })

    p2 = create_policy({
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "*",
        "Condition": {
            "StringNotEqual": { "foo": "baz" }
        },
    })

    assert not iam_policy_resolver.policies_are_equal(p1, p2)

