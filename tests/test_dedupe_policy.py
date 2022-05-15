import copy

from .context import aws_iam_utils
from aws_iam_utils.util import create_policy
from aws_iam_utils.util import statement
from aws_iam_utils.util import dedupe_policy

def test_dedupe_policy_actions():
    p = create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket', 's3:createbucket'], resource=["foo"], principal={"AWS":["bar"]}),
    )

    assert dedupe_policy(copy.deepcopy(p)) == create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket'], resource=["foo"], principal={"AWS":["bar"]}),
    )

def test_dedupe_policy_resources():
    p = create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket'], resource=["foo", 'bar', 'foo'], principal={"AWS":["bar"]}),
    )

    assert dedupe_policy(copy.deepcopy(p)) == create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket'], resource=["foo", 'bar'], principal={"AWS":["bar"]}),
    )

def test_dedupe_policy_aws_principals():
    p = create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket'], resource=["foo"], principal={"AWS":["bar", 'foo', 'bar']}),
    )

    assert dedupe_policy(copy.deepcopy(p)) == create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket'], resource=["foo"], principal={"AWS":["bar", 'foo']}),
    )

def test_dedupe_policy_service_principals():
    p = create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket'], resource=["foo"], principal={"Service":["bar", 'foo', 'bar']}),
    )

    assert dedupe_policy(copy.deepcopy(p)) == create_policy(
        statement(actions=["s3:listbucket", 's3:createbucket'], resource=["foo"], principal={"Service":["bar", 'foo']}),
    )
