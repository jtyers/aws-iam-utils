from fnmatch import fnmatch


class PolicyPermissionItem:
    """Defines a single permission that's granted in a policy."""

    def __init__(self, effect, action, resource=None, condition=None, principal=None):
        self.effect = effect
        self.action = action
        self.resource = resource
        self.condition = condition
        self.principal = principal

    def as_statement(self) -> dict:
        """Returns this PolicyPermissionItem as a Statement as it would
        appear in an IAM policy. (as a dict)"""
        result = {
            "Effect": self.effect,
            "Action": self.action,
        }

        if self.resource is not None:
            result["Resource"] = self.resource
        if self.condition is not None:
            result["Condition"] = self.condition
        if self.principal is not None:
            result["Principal"] = self.principal

        return result

    def matches_action(self, action):
        """Returns True if the action defined by this PolicyPermissionItem
        matches the given action. "Matches" means the actions are either
        equal (ignoring case) or they match after wildcards are considered.
        """
        return (
            action == self.action
            or action.lower() == self.action.lower()
            or fnmatch(action, self.action)
            or fnmatch(self.action, action)
        )

    def __as_dict(self):
        return {
            "effect": self.effect,
            "action": self.action,
            "resource": self.resource,
            "condition": self.condition,
            "principal": self.principal,
        }

    def __repr__(self):
        return f"PolicyPermissionItem({self.__as_dict()})"

    def __eq__(self, other):
        if type(other) is PolicyPermissionItem:
            return self.__as_dict() == other.__as_dict()
        else:
            return self.__as_dict() == other
