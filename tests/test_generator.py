import pytest
import copy

from .context import aws_iam_utils
from aws_iam_utils.util import create_policy
from aws_iam_utils.util import statement
from aws_iam_utils.constants import WILDCARD_ARN_TYPE

def test_generate_read_only_policy():
    p = aws_iam_utils.generator.generate_read_only_policy_for_service('s3')

    for statement in p['Statement']:
        for action in statement['Action']:
            assert action.startswith('s3:')

    assert aws_iam_utils.checks.is_read_only_policy(p)

def test_generate_read_write_policy():
    p = aws_iam_utils.generator.generate_read_write_policy_for_service('s3')

    for statement in p['Statement']:
        for action in statement['Action']:
            assert action.startswith('s3:')

    assert aws_iam_utils.checks.is_read_write_policy(p)

def test_generate_list_only_policy():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service('s3')

    for statement in p['Statement']:
        for action in statement['Action']:
            assert action.startswith('s3:')

    assert aws_iam_utils.checks.is_list_only_policy(p)

def test_generate_full_policy():
    p = aws_iam_utils.generator.generate_full_policy_for_service('s3')

    assert p == create_policy(
        statement(actions=["s3:*"], resource="*")
    )

def test_generate_read_only_policy_for_arn_type():
    p = aws_iam_utils.generator.generate_read_only_policy_for_service_arn_type('s3', 'bucket')

    assert aws_iam_utils.checks.is_read_only_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(p, 's3', ['bucket'])

def test_generate_read_write_policy_for_arn_type():
    p = aws_iam_utils.generator.generate_read_write_policy_for_service_arn_type('s3', 'bucket')

    assert aws_iam_utils.checks.is_read_write_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(p, 's3', ['bucket'])

def test_generate_list_only_policy_for_arn_type():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service_arn_type('s3', 'bucket')

    assert aws_iam_utils.checks.is_list_only_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(p, 's3', ['bucket'])

def test_generate_list_only_policy_for_arn_type_not_matching():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service_arn_type('s3', 'bucket')

    assert aws_iam_utils.checks.is_list_only_policy(p)
    assert not aws_iam_utils.checks.policy_has_only_these_arn_types(p, 's3', ['object'])

def test_generate_list_only_policy_for_wildcard_arn_type():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service_arn_type('s3', WILDCARD_ARN_TYPE)

    assert aws_iam_utils.checks.is_list_only_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(p, 's3', [WILDCARD_ARN_TYPE])

def test_generate_full_policy():
    p = aws_iam_utils.generator.generate_full_policy_for_service('s3')

    assert p == create_policy(
        statement(actions=["s3:*"], resource="*")
    )
