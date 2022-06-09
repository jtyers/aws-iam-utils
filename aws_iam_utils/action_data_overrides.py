from aws_iam_utils.constants import READ, WRITE, LIST

"""
This is a mapping of actions to overridden action data. This is primarily used to provide missing/incorrect results from policy_sentry's get_action_data.
"""
ACTION_DATA_OVERRIDES = {
  # NB: keys must be all lowercase
  'lambda:createfunctionurlconfig': {
    'action': 'lambda:createfunctionurlconfig',
    'access_level': WRITE,
  },
  'lambda:getfunctionurlconfig': {
    'action': 'lambda:getfunctionurlconfig',
    'access_level': READ,
  },
  'lambda:listfunctionurlconfigs': {
    'action': 'lambda:listfunctionurlconfigs',
    'access_level': LIST,
  },
  'events:listendpoints': {
    'action': 'events:listendpoints',
    'access_level': LIST,
  },
  'events:describeendpoint': {
    'action': 'describeendpoint:describeendpoint',
    'access_level': READ,
  },
  'wafv2:listmobilesdkreleases': {
    'action': 'wafv2:listmobilesdkreleases',
    'access_level': LIST,
  },
  'wafv2:getmobilesdkrelease': {
    'action': 'wafv2:getmobilesdkrelease',
    'access_level': READ,
  },
}
