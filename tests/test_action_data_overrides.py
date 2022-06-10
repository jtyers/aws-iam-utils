from policy_sentry.querying.actions import get_action_data
from aws_iam_utils.util import get_action_data_with_overrides
from aws_iam_utils.action_data_overrides import ACTION_DATA_OVERRIDES


def test_policy_sentry_actions_out_of_date():
    # verify that the actions we think are missing, are missing
    for action in ACTION_DATA_OVERRIDES:
        service_name, action_name = action.split(":")
        assert get_action_data(service_name, action_name) is False


def test_get_action_data_with_overrides():
    for action in ACTION_DATA_OVERRIDES:
        # action = 'lambda:getfunctionurlconfig'
        service_name, action_name = action.split(":")

        result = get_action_data_with_overrides(service_name, action_name)

        assert type(result) is dict
        assert result == {service_name: [ACTION_DATA_OVERRIDES[action]]}

        result_action = result[service_name][0]
        assert result_action["action"].lower() == action
