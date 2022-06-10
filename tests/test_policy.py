from aws_iam_utils.policy import PolicyPermissionItem
from aws_iam_utils.policy import policy_from_dict

from aws_iam_utils.util import extract_policy_permission_items
from aws_iam_utils.util import create_policy
from aws_iam_utils.util import statement
from aws_iam_utils.util import lowercase_policy
from aws_iam_utils.util import create_lowercase_policy


def test_create_policy_from_dict():
    policy = create_policy(statement(actions=["s3:PutObject", "s3:GetObject"]))

    p = policy_from_dict(policy)

    assert p.ppis == extract_policy_permission_items(policy)


def test_create_policy():
    policy = create_policy(statement(actions=["s3:PutObject", "s3:GetObject"]))

    p = policy_from_dict(policy)

    result = p.as_dict()

    assert result == lowercase_policy(policy)


def test_create_policy_after_adding_ppis():
    policy = create_policy(statement(actions=["s3:PutObject", "s3:GetObject"]))

    p = policy_from_dict(policy)
    p.ppis.append(PolicyPermissionItem("Allow", "s3:ListBucket"))
    p.ppis.append(PolicyPermissionItem("Allow", "s3:GetBucketPolicy"))
    p.ppis.append(PolicyPermissionItem("Allow", "s3:PutBucketPolicy"))

    result = p.as_dict()

    assert result == create_lowercase_policy(
        statement(
            actions=[
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:GetBucketPolicy",
                "s3:PutBucketPolicy",
            ]
        )
    )


def test_create_policy_after_adding_ppis_complex():
    policy = create_policy(
        statement(
            actions=["s3:PutObject", "s3:GetObject"], resource="arn:aws:s3:::my-bucket1"
        ),
    )

    p = policy_from_dict(policy)
    p.ppis.append(
        PolicyPermissionItem(
            "Allow", "s3:ListBucket", resource="arn:aws:s3:::my-bucket2"
        )
    )
    p.ppis.append(
        PolicyPermissionItem(
            "Allow", "s3:GetBucketPolicy", resource="arn:aws:s3:::my-bucket2"
        )
    )
    p.ppis.append(
        PolicyPermissionItem(
            "Allow",
            "s3:GetObject",
            resource="arn:aws:s3:::my-bucket3/foo/*",
            principal={"AWS": "arn:aws:iam:123456789012::role/foo"},
        )
    )

    result = p.as_dict()

    assert result == create_lowercase_policy(
        statement(
            actions=["s3:PutObject", "s3:GetObject"], resource="arn:aws:s3:::my-bucket1"
        ),
        statement(
            actions=["s3:ListBucket", "s3:GetBucketPolicy"],
            resource="arn:aws:s3:::my-bucket2",
        ),
        statement(
            actions=["s3:GetObject"],
            resource="arn:aws:s3:::my-bucket3/foo/*",
            principal={"AWS": "arn:aws:iam:123456789012::role/foo"},
        ),
    )


def test_find_action_ppis():
    policy = create_policy(
        statement(
            actions=["s3:PutObject", "s3:GetObject"], resource="arn:aws:s3:::my-bucket1"
        ),
        statement(
            actions=["s3:ListBucket", "s3:GetBucketPolicy"],
            resource="arn:aws:s3:::my-bucket2",
        ),
        statement(
            actions=["s3:GetObject"],
            resource="arn:aws:s3:::my-bucket3/foo/*",
            principal={"AWS": "arn:aws:iam:123456789012::role/foo"},
        ),
    )

    p = policy_from_dict(policy)

    result = p.find_action_ppis("s3:GetObject")

    assert result == [
        PolicyPermissionItem(
            "Allow", "s3:getobject", resource="arn:aws:s3:::my-bucket1"
        ),
        PolicyPermissionItem(
            "Allow",
            "s3:getobject",
            resource="arn:aws:s3:::my-bucket3/foo/*",
            principal={"AWS": "arn:aws:iam:123456789012::role/foo"},
        ),
    ]
