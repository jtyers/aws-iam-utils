from policyuniverse.expander_minimizer import expand_policy

from .context import aws_iam_utils
from aws_iam_utils.util import create_policy
from aws_iam_utils.util import statement
from aws_iam_utils.constants import READ, LIST, WILDCARD_ARN_TYPE


def test_generate_read_only_policy():
    p = aws_iam_utils.generator.generate_read_only_policy_for_service("s3")

    assert aws_iam_utils.checks.is_read_only_policy(p)
    assert p == create_policy(
        statement(
            actions=[
                "s3:Describe*",
                "s3:Get*",
                "s3:List*",
            ],
            resource="*",
        )
    )


def test_generate_read_write_policy():
    p = aws_iam_utils.generator.generate_read_write_policy_for_service("s3")

    for st in p["Statement"]:
        for action in st["Action"]:
            assert action.startswith("s3:")

    assert aws_iam_utils.checks.is_read_write_policy(p)


def test_generate_list_only_policy():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service("s3")

    assert aws_iam_utils.checks.is_list_only_policy(p)
    assert p == create_policy(statement(actions=["s3:List*"], resource="*"))


def test_generate_full_policy():
    p = aws_iam_utils.generator.generate_full_policy_for_service("s3")

    assert p == create_policy(statement(actions=["s3:*"], resource="*"))


def test_generate_read_only_policy_for_arn_type():
    p = aws_iam_utils.generator.generate_read_only_policy_for_service_arn_type(
        "s3", "bucket"
    )

    assert aws_iam_utils.checks.is_read_only_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(p, "s3", ["bucket"])


def test_generate_read_write_policy_for_arn_type():
    p = aws_iam_utils.generator.generate_read_write_policy_for_service_arn_type(
        "s3", "bucket"
    )

    assert aws_iam_utils.checks.is_read_write_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(p, "s3", ["bucket"])


def test_generate_list_only_policy_for_arn_type():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service_arn_type(
        "s3", "bucket"
    )

    assert aws_iam_utils.checks.is_list_only_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(p, "s3", ["bucket"])


def test_generate_list_only_policy_for_arn_type_not_matching():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service_arn_type(
        "s3", "bucket"
    )

    assert aws_iam_utils.checks.is_list_only_policy(p)
    assert not aws_iam_utils.checks.policy_has_only_these_arn_types(p, "s3", ["object"])


def test_generate_list_only_policy_for_wildcard_arn_type():
    p = aws_iam_utils.generator.generate_list_only_policy_for_service_arn_type(
        "s3", WILDCARD_ARN_TYPE
    )

    assert aws_iam_utils.checks.is_list_only_policy(p)
    assert aws_iam_utils.checks.policy_has_only_these_arn_types(
        p, "s3", [WILDCARD_ARN_TYPE]
    )


def test_generate_policy_for_service_uses_action_data_overrides():
    # events:describeendpoint is a known action that needs an override,
    # so generate a policy that contains it
    p = aws_iam_utils.generator.generate_policy_for_service("events", [LIST, READ])
    assert "events:describeendpoint" in expand_policy(p)["Statement"][0]["Action"]


def test_generate_policy_for_service_includes_wildcard_actions():
    # ec2:DescribeFlowLogs and ssm:DescribeParameters are both actions
    # for wildcard resources (i.e. you grant Resource = "*")
    p = aws_iam_utils.generator.generate_policy_for_service("ssm", [LIST, READ])
    assert "ssm:describeparameters" in expand_policy(p)["Statement"][0]["Action"]

    p = aws_iam_utils.generator.generate_policy_for_service("ec2", [LIST, READ])
    assert "ec2:describeflowlogs" in expand_policy(p)["Statement"][0]["Action"]


def test_generate_policy_for_service_arn_type_includes_wildcard_actions():
    # ec2:DescribeFlowLogs and ssm:DescribeParameters are both actions
    # for wildcard resources (i.e. you grant Resource = "*")
    p = aws_iam_utils.generator.generate_policy_for_service_arn_type(
        "ssm", "parameter", [LIST, READ], include_service_wide_actions=True
    )
    assert "ssm:describeparameters" in expand_policy(p)["Statement"][0]["Action"]

    p = aws_iam_utils.generator.generate_policy_for_service_arn_type(
        "ec2", "vpc-flow-log", [LIST, READ], include_service_wide_actions=True
    )
    assert "ec2:describeflowlogs" in expand_policy(p)["Statement"][0]["Action"]


def test_generate_policy_for_service_arn_type_excludes_wildcard_actions():
    # ec2:DescribeFlowLogs and ssm:DescribeParameters are both actions
    # for wildcard resources (i.e. you grant Resource = "*")
    p = aws_iam_utils.generator.generate_policy_for_service_arn_type(
        "ssm", "parameter", [LIST, READ], include_service_wide_actions=False
    )
    assert "ssm:describeparameters" not in expand_policy(p)["Statement"][0]["Action"]

    p = aws_iam_utils.generator.generate_policy_for_service_arn_type(
        "ec2", "vpc-flow-log", [LIST, READ], include_service_wide_actions=False
    )
    assert "ec2:describeflowlogs" not in expand_policy(p)["Statement"][0]["Action"]
