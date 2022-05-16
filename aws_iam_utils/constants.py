# Access levels as they appear in the raw AWS IAM data returned by get_action_data
# (see https://raw.githubusercontent.com/salesforce/policy_sentry/master/policy_sentry/shared/data/iam-definition.json)
READ = "Read"
LIST = "List"
WRITE = "Write"
TAGGING = "Tagging"
PERMISSIONS = "Permissions management"

ALL_ACCESS_LEVELS = [ READ, LIST, WRITE, TAGGING, PERMISSIONS ]

WILDCARD_ARN_TYPE = '*'
