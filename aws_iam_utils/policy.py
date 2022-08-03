from aws_iam_utils.util import extract_policy_permission_items
from aws_iam_utils.combiner import collapse_policy_statements
from aws_iam_utils.policy_permission_item import PolicyPermissionItem


def policy_from_dict(policy):
    ppis = [PolicyPermissionItem(**x) for x in extract_policy_permission_items(policy)]

    return Policy(version=policy["Version"], ppis=ppis)


class Policy:
    def __init__(self, version: str, ppis: list[PolicyPermissionItem]):
        self.version = version
        self.ppis = ppis

    def as_dict(self):
        statements = [p.as_statement() for p in self.ppis]

        return collapse_policy_statements(
            {
                "Version": self.version,
                "Statement": statements,
            }
        )

    def find_action_ppis(self, action_name):
        l_action_name = action_name.lower()
        result = []
        for ppi in self.ppis:
            if ppi.action.lower() == l_action_name:
                result.append(ppi)

        return result

    def add_policy_statements(self, policy):
        """Adds statements from the given policy into this policy."""
        self.ppis.extend(policy_from_dict(policy).ppis)
