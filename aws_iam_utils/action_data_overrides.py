from aws_iam_utils.constants import READ, WRITE, LIST

"""
This is a mapping of actions to overridden action data. This is primarily used to provide missing/incorrect results from policy_sentry's get_action_data.
"""
ACTION_DATA_OVERRIDES = {
    x['action'].lower() : x for x in [
        {
            'action': 'lambda:CreateFunctionUrlConfig',
            'access_level': WRITE,
        },
        {
            'action': 'lambda:GetFunctionurlConfig',
            'access_level': READ,
        },
        {
            'action': 'lambda:DeleteFunctionUrlConfig',
            'access_level': WRITE,
        },
        {
            'action': 'lambda:UpdateFunctionUrlConfig',
            'access_level': WRITE,
        },
        {
            'action': 'lambda:ListFunctionurlConfigs',
            'access_level': LIST,
        },
        {
            'action': 'lambda:InvokeFunctionUrl',
            'access_level': READ,
        },
        {
            'action': 'events:ListEndpoints',
            'access_level': LIST,
        },
        {
            'action': 'events:DescribEendpoint',
            'access_level': READ,
        },
        {
            'action': 'wafv2:ListMobileSdkReleases',
            'access_level': LIST,
        },
        {
            'action': 'wafv2:GetMobileSdkRelease',
            'access_level': READ,
        },
    ]
}
