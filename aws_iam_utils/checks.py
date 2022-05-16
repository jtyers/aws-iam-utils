import sys
import json

from policyuniverse.expander_minimizer import expand_policy
from policy_sentry.querying.actions import get_actions_matching_arn_type
from policy_sentry.querying.actions import get_actions_that_support_wildcard_arns_only

from aws_iam_utils.constants import READ, LIST, WRITE, WILDCARD_ARN_TYPE
from aws_iam_utils.util import extract_policy_permission_items
from aws_iam_utils.util import get_action_data_with_overrides

def policies_are_equal(p1, p2):
    """
    Checks whether two policies give the same permissions. This will expand all wildcards and Resource constraints and then compare the result.

    @param p1  The first policy. Should be a dict that contains a Statement key, which should be a list of dicts conforming to the AWS IAM Policy schema.
    @param p2  The second policy, same format as p1.

    @returns True if p1 and p2 represent exactly the same permissions, or False otherwise.
    """
    return extract_policy_permission_items(expand_policy(p1)) == extract_policy_permission_items(expand_policy(p2))

def policy_has_only_these_access_levels(p, access_levels):
    """
    Returns True if all actions granted under the given policy are Read or List actions.
    """
    p_items = extract_policy_permission_items(expand_policy(p))
    for item in p_items:
        action_service, action_name = item["action"].split(":")

        action_output = get_action_data_with_overrides(action_service, action_name)

        if action_output is False:
            raise ValueError(f'invalid action: {item["action"]}')

        for action_output_action in action_output[action_service]:
            if action_output_action["action"].lower() != item["action"].lower():
                continue

            if action_output_action["access_level"] not in access_levels:
                return False

    return True


def is_read_only_policy(p):
    """
    Returns True if all actions granted under the given policy are Read or List actions.
    """
    return policy_has_only_these_access_levels(p, [ READ, LIST ])


def is_list_only_policy(p):
    """
    Returns True if all actions granted under the given policy are List actions.
    """
    return policy_has_only_these_access_levels(p, [ LIST ])


def is_read_write_policy(p):
    """
    Returns True if all actions granted under the given policy are Read, List or Write actions.
    """
    return policy_has_only_these_access_levels(p, [ READ, LIST, WRITE ])

def policy_has_only_these_arn_types(p, service_name, arn_types):
    """
    Returns True if all actions granted under the given policy relate to the given ARN types only. Use `aws_iam_utils.constants.WILDCARD_ARN_TYPE` to refer to actions that do not relate to an ARN type (so-called "wildcard actions" in policy_sentry).
    """
    arn_type_actions = {}
    for arn_type in arn_types:
        if arn_type == WILDCARD_ARN_TYPE:
            arn_type_actions[arn_type] = [ x.lower() for x in get_actions_that_support_wildcard_arns_only(service_name) ]
        else:
            arn_type_actions[arn_type] = [ x.lower() for x in get_actions_matching_arn_type(service_name, arn_type) ]

    p_items = extract_policy_permission_items(expand_policy(p))
    for item in p_items:
        action_service, action_name = item["action"].split(":")

        action_output = get_action_data_with_overrides(action_service, action_name)

        if action_output is False:
            raise ValueError(f'invalid action: {item["action"]}')

        action_found = False
        for arn_type in arn_types:
            if item['action'].lower() in arn_type_actions[arn_type]:
                action_found = True
                break

        if action_found is False:
            return False

    return True


