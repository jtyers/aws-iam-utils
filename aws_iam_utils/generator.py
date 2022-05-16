import re
import sys

from policy_sentry.querying.actions import get_actions_for_service
from policy_sentry.querying.actions import get_actions_matching_arn_type

from aws_iam_utils import checks
from aws_iam_utils.util import create_policy
from aws_iam_utils.util import get_action_data_with_overrides
from aws_iam_utils.util import statement
from aws_iam_utils.constants import READ, LIST, WRITE

def generate_read_only_policy_for_service(service_name, use_wildcard_verbs=True):
    """Generates an IAM policy that grants read-only access to all of the given service."""
    return generate_policy_for_service(service_name, [ LIST, READ ], use_wildcard_verbs=use_wildcard_verbs)

def generate_list_only_policy_for_service(service_name, use_wildcard_verbs=True):
    """Generates an IAM policy that grants list-only access to all of the given service."""
    return generate_policy_for_service(service_name, [ LIST ], use_wildcard_verbs=use_wildcard_verbs)

def generate_read_write_policy_for_service(service_name, use_wildcard_verbs=True):
    """Generates an IAM policy that grants read-write access to all of the given service."""
    return generate_policy_for_service(service_name, [ LIST, READ, WRITE ], use_wildcard_verbs=use_wildcard_verbs)

def generate_read_only_policy_for_service_arn_type(service_name, arn_type):
    """Generates an IAM policy that grants read-only access to all of the given service."""
    return generate_policy_for_service_arn_type(service_name, arn_type, [ LIST, READ ])

def generate_list_only_policy_for_service_arn_type(service_name, arn_type):
    """Generates an IAM policy that grants list-only access to all of the given service."""
    return generate_policy_for_service_arn_type(service_name, arn_type, [ LIST ])

def generate_read_write_policy_for_service_arn_type(service_name, arn_type):
    """Generates an IAM policy that grants read-write access to all of the given service."""
    return generate_policy_for_service_arn_type(service_name, arn_type, [ LIST, READ, WRITE ])

def generate_full_policy_for_service(*service_name):
    """Generates an IAM policy that grants full access to all of the given service."""
    return create_policy({
        "Effect": "Allow",
        "Action": [ f"{s}:*" for s in service_name ],
        "Resource": "*",
    })

def generate_policy_for_service_arn_type(service_name, arn_type, reqd_access_levels):
    """
    Generates an IAM policy that grants the given level of access to a specific ARN type within the given AWS service.

    Use `policy_sentry query arn-table --service <service>` to query ARN types available for a service.

    If use_wildcard_verbs is True (the default), the generator will try to use use verb wildcards (e.g. "s3:Get*") rather than full action names to keep the policy short and readable.

    The generator always verifies that the generated policy only grants permissions in the given access level. If this check fails when use_wildcard_verbs is True, the full action list is returned. If the check still fails with the full action list, an AssertionError is raised, and this indicates an underlying bug in the policy data driving aws-iam-utils.
    """
    service_actions = get_actions_matching_arn_type(service_name, arn_type)

    # use_wildcard_verbs is False here as it'll always fail (verb-based 
    # wildcards will always matching more than one ARN type)
    return __generate_and_validate_policy_from_actions(service_actions, service_name, reqd_access_levels, use_wildcard_verbs=False)

def generate_policy_for_service(service_name, reqd_access_levels, use_wildcard_verbs=True):
    """
    Generates an IAM policy that grants the given level of access to all of the given AWS service.

    If use_wildcard_verbs is True (the default), the generator will try to use use verb wildcards (e.g. "s3:Get*") rather than full action names to keep the policy short and readable.

    The generator always verifies that the generated policy only grants permissions in the given access level. If this check fails when use_wildcard_verbs is True, the full action list is returned. If the check still fails with the full action list, an AssertionError is raised, and this indicates an underlying bug in the policy data driving aws-iam-utils.
    """
    service_actions = get_actions_for_service(service_name)

    return __generate_and_validate_policy_from_actions(service_actions, service_name, reqd_access_levels, use_wildcard_verbs)


def __generate_and_validate_policy_from_actions(service_actions, service_name, reqd_access_levels, use_wildcard_verbs):
    matching_actions = []
    policy = None

    for action in service_actions:
        action_service, action_name = action.split(':')

        # iterate through each action and pull out read-only actions
        action_output = get_action_data_with_overrides(action_service, action_name)

        if action_output is False:
            raise ValueError(f'invalid action: {action_name}')

        for action_output_action in action_output[service_name]:
            if action_output_action["access_level"] in reqd_access_levels and action_output_action['action'] not in matching_actions:
                matching_actions.append(action_output_action["action"])

    if use_wildcard_verbs:
        # In this mode, we deduce the 'verb' (first word, assuming camel case) of each
        # action in the list and try to shorten the list to those verbs, wildcarded.
        # This approach makes for way shorter and easier-to-read policies.
        wildcarded_matching_actions = []

        for action in matching_actions:
            action_service, action_name = action.split(':')

            parts = list(filter(lambda x: len(x)>0, re.split('([A-Z])', action_name, 2)))

            if len(parts) >= 4:
                # 'DescribeJobAspectsPolicy' -> ['D', 'escribe', 'J', 'obAspectsPolicy']
                verb = parts[0]+parts[1]
                wildcarded_verb = f'{service_name}:{verb}*'

                if 'Policy' not in action_name and 'Tagging' not in action_name and wildcarded_verb not in wildcarded_matching_actions:
                    wildcarded_matching_actions.append(wildcarded_verb)

            else:
                wildcarded_matching_actions.append(action)

        policy = create_policy(statement(actions=wildcarded_matching_actions, resource='*'))

    else:
        policy = create_policy(statement(actions=matching_actions, resource='*'))

    if use_wildcard_verbs:
        # in this mode, check the policy is not too permissive and if so,
        # fall back to the full action list
        if not checks.policy_has_only_these_access_levels(policy, reqd_access_levels):
            policy = create_policy(statement(actions=matching_actions, resource='*'))

    assert checks.policy_has_only_these_access_levels(policy, reqd_access_levels)

    return policy
