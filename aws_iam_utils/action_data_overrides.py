"""
This is a mapping of actions to overridden action data. This is primarily used to provide missing/incorrect results from policy_sentry's get_action_data.
"""
ACTION_DATA_OVERRIDES = {
  # NB: keys must be all lowercase
  'lambda:getfunctionurlconfig': {
      'action': 'lambda:getfunctionurlconfig',
      "access_level": "Read",
      "api_documentation_link": "https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunctionUrlConfig.html",
  }
}
