def simplify_policy(p):
  """For the given policy, simplify any one-item arrays into straight strings, for Actions, Principals and Resources."""

  statements = p['Statement']

  for statement in statements:
    for k in [ "Action", "Resource" ]:
      if k in statement:
        if type(statement[k]) is list and len(statement[k]) == 1:
            statement[k] = statement[k][0]

    if 'Principal' in statement:
        principal = statement['Principal']

        for k in [ "AWS", "Service" ]:
          if k in principal:
            if type(principal[k]) is list and len(principal[k]) == 1:
                principal[k] = principal[k][0]

  return p
