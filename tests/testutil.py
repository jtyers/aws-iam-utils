from aws_iam_utils.util import create_policy

def lowercase_policy(p):
    """Returns policy p, but with all actions and effects in lowercase, to match the behaviour of policyuniverse-expanded policies, so we can easily compare policies."""
    new_statements = []

    for statement in p['Statement']:
        new_statement = {}

        for key in [ "Effect", "Action" ]:
            if key in statement:
                if type(statement[key]) is list:
                    new_statement[key] = [ s.lower() for s in statement[key] ]
                else:
                    new_statement[key] = statement[key].lower()

        new_statements.append(new_statement)

        for key in [ "Principal", "Condition", "Resource" ]:
            if key in statement:
                new_statement[key] = statement[key]

    return {
        "Version": p['Version'],
        "Statement": new_statements,
    }


def create_lowercase_policy(*st):
    """Simply wraps create_policy and lowercase_policy, creating a policy with lowercase actions and effects regardless of the inputs."""
    return lowercase_policy(create_policy(*st))
