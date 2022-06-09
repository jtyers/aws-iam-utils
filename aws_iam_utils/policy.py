from aws_iam_utils.util import extract_policy_permission_items
from aws_iam_utils.combiner import collapse_policy_statements

def policy_from_dict(policy):
  ppis = [ PolicyPermissionItem(**x) for x in extract_policy_permission_items(policy) ]

  return Policy(version=policy['Version'], ppis=ppis)

class PolicyPermissionItem:
  def __init__(self, effect, action, resource=None, condition=None, principal=None):
    self.effect = effect
    self.action = action
    self.resource   = resource
    self.condition = condition
    self.principal = principal

  def as_statement(self):
    result = {
      'Effect': self.effect,
      'Action': self.action,
    }

    if self.resource != None:
      result['Resource'] = self.resource
    if self.condition != None:
      result['Condition'] = self.condition
    if self.principal != None:
      result['Principal'] = self.principal

    return result

  def __as_dict(self):
    return {
      'effect': self.effect,
      'action': self.action,
      'resource': self.resource,
      'condition': self.condition,
      'principal': self.principal,
    }

  def __repr__(self):
      return f'PolicyPermissionItem({self.__as_dict()})'

  def __eq__(self, other):
    if type(other) is PolicyPermissionItem:
        return self.__as_dict() == other.__as_dict()
    else:
        return self.__as_dict() == other


class Policy:
  def __init__(self, version: str, ppis: list[PolicyPermissionItem]):
    self.version = version
    self.ppis = ppis

  def as_dict(self):
    statements = [ p.as_statement() for p in self.ppis ]

    return collapse_policy_statements({
        'Version': self.version,
        'Statement': statements,
    })

  def find_action_ppis(self, action_name):
    l_action_name = action_name.lower()
    result = []
    for ppi in self.ppis:
        if ppi.action.lower() == l_action_name:
            result.append(ppi)

    return result
