from policyuniverse.expander_minimizer import expand_policy
from policy_sentry.querying.actions import get_action_data
from aws_iam_utils.action_data_overrides import ACTION_DATA_OVERRIDES

def create_policy(*statements, version="2012-10-17"):
    """Shortcut function to create a policy with the given statements."""
    return {
        "Version": version,
        "Statement": list(statements)
    }

def statement(effect="Allow", actions=[], resource=None, condition=None, principal=None):
    """Shortcut function to create a Statement with the given properties."""
    st = {}

    for k, v in {
        "Effect": effect,
        "Action": actions,
        "Resource": resource,
        "Principal": principal,
        "Condition": condition,
    }.items():
        if v is not None: st[k] = v

    return st


def extract_policy_permission_items(policy, allow_unsupported=False):
    """
    For every individual permission granted, we build a list of
    { permission, resource, condition, principal } ("permission items").

    The policy is always expanded via expand_policy() first.

    This is useful for comparisons. Currently it does NOT support NotAction, NotPrincipal, NotResource keys. The presences of those keys will result in an exception, unless allow_unsupported is True.
    """

    items = []

    policy_expanded = policy

    for statement in policy_expanded["Statement"]:
        if not allow_unsupported:
            for k in [ "NotAction", "NotPrincipal", "NotResource" ]:
                if k in statement:
                    raise ValueError(f'Policy key {k} is not supported by extract_policy_permission_items() and will be ignored. To ignore this error, call extract_policy_permission_items with allow_unsupported=True.')


        for k in [ "Action", "Resource" ]:
            if type(statement.get(k)) is str:  # turn into list
                statement[k] = [statement[k]]
            
        effect = statement.get("Effect")
        condition = statement.get("Condition")
        principal = statement.get("Principal")

        for resource in statement.get("Resource", [None]):
            for action in statement["Action"]:
                items.append({
                    "effect": effect,
                    "action": action.lower(),
                    "resource": resource,
                    "condition": condition,
                    "principal": principal,
                })

    return items


def dedupe_list(lst):
    return sorted(set(lst), key=lambda x: lst.index(x))

def dedupe_policy(policy):
    """Deduplicates all Actions, Principals and Resources in the given policy."""
    for statement in policy["Statement"]:
        for k in [ "Action", "Resource" ]:
            if type(statement.get(k)) is list:
                statement[k] = dedupe_list(statement[k])
        
        principal = statement.get("Principal")
        for k in [ "AWS", "Service" ]:
            if type(principal.get(k)) is list:
                principal[k] = dedupe_list(principal[k])

    return policy

def get_action_data_with_overrides(service_name, action_name):
    full_action_name = f'{service_name}:{action_name.lower()}'
    if full_action_name in ACTION_DATA_OVERRIDES:
        return {
            service_name: [
                ACTION_DATA_OVERRIDES[full_action_name]
            ]
        }

    return get_action_data(service_name, action_name)
