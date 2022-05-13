import pytest
import random
import copy

from policyuniverse.expander_minimizer import minimize_policy
from .context import aws_iam_utils

def create_policy(*statements):
    return {
        "Version": "2012-10-17",
        "Statement": statements
    }

def test_policy_is_read_only_with_single_read_only_op():
    p = create_policy({
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "*",
    })

    assert aws_iam_utils.checks.is_read_only_policy(p)

def test_policy_is_read_only_with_list_only_ops():
    p = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:ListBucket",
            "s3:ListBucketVersions",
        ],
        "Resource": "*",
    })

    assert aws_iam_utils.checks.is_read_only_policy(p)

def test_policy_is_read_only_with_read_only_ops():
    p = create_policy({
        "Effect": "Allow",
        "Action": [
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

    assert aws_iam_utils.checks.is_read_only_policy(p)

def test_policy_is_read_only_with_read_only_ops_via_wildcards():
    p = minimize_policy(create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:GetObjectVersion",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionAttributes",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionTorrent",
            "s3:GetObject",
        ],
        "Resource": "*",
    }))

    assert aws_iam_utils.checks.is_read_only_policy(p)

def test_policy_is_not_read_only_with_write_ops():
    p = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:GetObjectVersion",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionAttributes",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionTorrent",
            "s3:GetObject",
            "s3:PutObject",
        ],
        "Resource": "*",
    })

    assert not aws_iam_utils.checks.is_read_only_policy(p)

def test_policy_is_not_read_only_with_permmgmt_ops():
    p = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:GetObjectVersion",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionAttributes",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionTorrent",
            "s3:GetObject",
            "s3:PutBucketPolicy",
        ],
        "Resource": "*",
    })

    assert not aws_iam_utils.checks.is_read_only_policy(p)

def test_policy_is_not_read_only_with_tagging_ops():
    p = create_policy({
        "Effect": "Allow",
        "Action": [
            "s3:GetObjectVersion",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionAttributes",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionTorrent",
            "s3:GetObject",
            "s3:PutBucketTagging",
        ],
        "Resource": "*",
    })

    assert not aws_iam_utils.checks.is_read_only_policy(p)
