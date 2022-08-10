from aws_iam_utils.policy import policy_from_dict
from aws_iam_utils.util import extract_action_components

from policyuniverse.expander_minimizer import _expand_wildcard_action


def simplify_policy(p: dict) -> dict:
    """For the given policy, simplify any one-item arrays into straight strings, for
    Actions, Principals and Resources."""

    statements = p["Statement"]

    for statement in statements:
        for k in ["Action", "Resource"]:
            if k in statement:
                if type(statement[k]) is list and len(statement[k]) == 1:
                    statement[k] = statement[k][0]

        if "Principal" in statement:
            principal = statement["Principal"]

            for k in ["AWS", "Service"]:
                if k in principal:
                    if type(principal[k]) is list and len(principal[k]) == 1:
                        principal[k] = principal[k][0]

    return p


def introduce_wildcards(p: dict) -> dict:
    """
    For the given policy, try to reduce actions down to wildcards
    if possible in order to make the policy easier to read.
    """

    policy = policy_from_dict(p)

    service_verbs = {}

    for ppi in policy.ppis:
        # 'DescribeAPIDetails' -> ['Describe', 'APIDetails']
        # 'GetBucketPolicy' -> ['Get', 'BucketPolicy']

        service, verb, subject = extract_action_components(ppi.action)

        service_verb = f"{service}:{verb}"
        if service_verb not in service_verbs:
            service_verbs[service_verb] = []

        service_verbs[service_verb].append(subject)

    # for every (service, verb) combo
    # - 'try' "<service>:<verb>*"
    # - gather the full list of actions that wildcard matches
    # - compare that with matching actions in the policy
    # - if they're equal, replace all matching entries with that wildcard in the policy

    print(f"{service_verbs}")
    for service_verb in service_verbs.keys():
        all_actions = _expand_wildcard_action(f"{service_verb}*")

        print(f"{service_verb}*: {all_actions}")
