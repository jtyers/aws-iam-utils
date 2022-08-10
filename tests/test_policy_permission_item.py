from aws_iam_utils.policy import PolicyPermissionItem


def test_policy_permission_item_matches_action():
    ppi = PolicyPermissionItem(effect="Allow", action="s3:PutObject")

    assert ppi.matches_action("s3:PutObject")


def test_policy_permission_item_matches_action_differing_case():
    ppi = PolicyPermissionItem(effect="Allow", action="s3:PutObject")

    assert ppi.matches_action("S3:PUTOBJECT")


def test_wildcard_policy_permission_item_matches_action():
    ppi = PolicyPermissionItem(effect="Allow", action="s3:Put*")

    assert ppi.matches_action("s3:PutObject")


def test_policy_permission_item_matches_wildcard_action():
    ppi = PolicyPermissionItem(effect="Allow", action="s3:PutObject")

    assert ppi.matches_action("s3:Put*")
