from policy_sentry.querying.actions import get_actions_for_service
from policy_sentry.querying.actions import get_action_data

from aws_iam_utils import checks
from aws_iam_utils.util import create_policy
from aws_iam_utils.constants import READ, LIST, WRITE

def generate_read_only_policy_for_service(service_name):
    return generate_policy_for_service(service_name, [ LIST, READ ])

def generate_list_only_policy_for_service(service_name):
    return generate_policy_for_service(service_name, [ LIST ])

def generate_read_write_policy_for_service(service_name):
    return generate_policy_for_service(service_name, [ LIST, READ, WRITE ])

def generate_full_policy_for_service(*service_name):
    return create_policy({
        "Effect": "Allow",
        "Action": [ f"{s}:*" for s in service_name ],
        "Resource": "*",
    })

def generate_policy_for_service(service_name, reqd_access_levels):
    service_actions = get_actions_for_service(service_name)

    matching_actions = []

    for action in service_actions:
        action_service, action_name = action.split(':')

        # iterate through each action and pull out read-only actions
        action_output = get_action_data(action_service, action_name)

        if action_output is False:
            raise ValueError(f'invalid action: {action_name}')

        for action_output_action in action_output[service_name]:
            if action_output_action["access_level"] in reqd_access_levels:
                matching_actions.append(action_output_action["action"])

    policy = create_policy({
        "Effect": "Allow",
        "Action": matching_actions,
        "Resource": "*",
    })

    assert checks.policy_has_only_these_access_levels(policy, reqd_access_levels)

    return policy
