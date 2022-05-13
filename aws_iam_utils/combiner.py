import json
from itertools import chain

from aws_iam_utils.util import extract_policy_permission_items
from aws_iam_utils.util import create_policy

def combine_policy_statements(*policies):
    """
    Merges the Statements for all the given policies into a single policy.
    """

    if len(policies) == 0:
        return create_policy()

    return create_policy(
        *list(chain(*[ p['Statement'] for p in policies ])),
        version=policies[0]["Version"],
    )

def collapse_policy_statements(*policies):
    """
    Attempts to merge policy statements together as far as possible, in order to simplify and shorten your policy. All statements with equal Effect, Condition, Principal and Resource keys will have their Actions merged together.
    """

    # create a single policy with all Statements combined together
    combined_policy = combine_policy_statements(*policies)

    items = extract_policy_permission_items(combined_policy)

    # to combine, we group all actions by their effect/resource/condition/principal,
    # and then generate a new policy with statements for each unique combination
    # of those
    actions_by_qualifiers = {}

    for item in items:
        # turn into json so we can use nested dicts/lists/etc as dict keys
        k = json.dumps([item['effect'], item['condition'], item['resource'], item['principal']])

        if not k in actions_by_qualifiers:
            actions_by_qualifiers[k] = []

        actions_by_qualifiers[k].append(item['action'])

    new_policy_statements = []
    for qualifiers, actions in actions_by_qualifiers.items():
        new_statement = {}
        qualifiers_loaded = json.loads(qualifiers)

        for k, v in {
            "Effect": qualifiers_loaded[0],
            "Condition": qualifiers_loaded[1],
            "Resource": qualifiers_loaded[2],
            "Principal": qualifiers_loaded[3],
        }.items():
            if v is not None: new_statement[k] = v

        new_statement["Action"] = actions

        new_policy_statements.append(new_statement)

    return {
        "Version": combined_policy["Version"],
        "Statement": new_policy_statements
    }
