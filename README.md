# aws-iam-utils

aws-iam-utils is a Python library with some utility functions for working with AWS IAM policies. I wrote this because, although many awesome AWS utility libraries exist, there was no simple toolset I could find that brings them together for practical use when you want the minimum code/scripting to get things done, particularly without learning a complex API.

aws-iam-utils allows you to:

* check if two policies provide the same permissions (taking account of wildcards)

* check the level of access a policy provides (i.e. list, read-only, write, tagging or permissions-management) so you can verify that a policy does what you think it does

* combine two policies together (i.e. merge their `Statement`s)

* collapse multiple policies in order to minimise or enhance readability (see below)

* generate list-only, read-only, read-write or full-access policies for any AWS service (with built-in assertions that the generated policies are correct according to the checks above)

* simplify policies by changing arrays for Actions, Resources and Principals into strings if they contain only one item

There is an extensive test suite covering all features. Remember it is your responsibility to use this code wisely and satisfy yourself that its outputs are secure for your needs.

All the data that supports the policy generation and access levels comes from the excellent `policyuniverse` and `policy_sentry` libraries, which in turn get their data from AWS's own API documentation.

## Examples

Here are simple examples for all the use cases above. More example code can be found in the `tests` directory.

### Check if two policies are equal

```python
from aws_iam_utils.checks import policies_are_equal

first_policy = {
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
        "s3:PutObject",
        "s3:PutObjectVersionAcl",
        "s3:PutObjectVersionTagging",
    ],
    "Resource": "*",
  }]
}

second_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "*",
    },
    {
      "Effect": "Allow",
      "Action": [
          "s3:PutObjectVersionAcl",
          "s3:PutObjectVersionTagging",
      ],
      "Resource": "*",
    }
  ]
}

print(policies_are_equal(first_policy, second_policy))
# True
```

### Check the level of access a policy provides

```python
from aws_iam_utils.checks import is_list_only_policy
from aws_iam_utils.util import create_policy

p = create_policy({
¦   "Effect": "Allow",
¦   "Action": [
¦   ¦   "s3:ListBucket",
¦   ¦   "s3:ListBucketVersions",
¦   ¦   "s3:GetObjectVersion",
¦   ],
¦   "Resource": "*",
})

print(aws_iam_utils.checks.is_list_only_policy(p))
# False (because GetObjectVersion is a read operation)
```

There is also `is_read_only_policy()` (which returns True if the policy allows only read and list operations), and `is_read_write_policy()` (which returns True if the policy allows only read, list and write operations, but not tagging or permissions management operations).

Notice the call to `create_policy()`? This is a simple function that creates the boilerplate `Version` and `Statement` fields for you, simply pass in one or more `Statement`s as dicts. It helps to cut down (just slightly) on repetitive code. The latest version (`2012-10-17`) is used by default but can be overridden with `create_policy(..., version='new_version')`. Using `create_policy` is completely optional.

### Combine policies together

`aws-iam-utils` allows you to merge policy documents, which simply means concatenating `Statement`s together. This is useful for policies generated elsewhere (e.g. by `aws_iam_utils` or other tools) that you want to use together.

```python
from aws_iam_utils.combiner import combine_policy_statements

first_policy = {
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
        "s3:PutObject",
        "s3:PutObjectVersionAcl",
        "s3:PutObjectVersionTagging",
    ],
    "Resource": "*",
  }]
}

second_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
          "s3:PutObjectVersionAcl",
          "s3:PutObjectVersionTagging",
      ],
      "Resource": "*",
    }
  ]
}

print(combine_policy_statements(first_policy, second_policy))
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": [
#           "s3:PutObjectVersionAcl",
#           "s3:PutObjectVersionTagging",
#       ],
#       "Resource": "*",
#     },
#     {
#       "Effect": "Allow",
#       "Action": [
#           "s3:PutObject",
#           "s3:PutObjectVersionAcl",
#           "s3:PutObjectVersionTagging",
#       ],
#       "Resource": "*",
#     }
#   ]
# }
```

`combine_policy_statements` is a simple concatenation of `Statement`s with no intelligence whatsoever. If you also want to merge `Statement`s together where it is safe to do so, see collapsing in the next section.

### Collapse policies together

Where *combining* policies is a simple concatenation operation, *collapsing* one or more policies examines the statements and merges together those statements that apply the same effect to the same Principals, Resources and Conditions.

For example, let's repeat the example we had above:

```python
from aws_iam_utils.combiner import collapse_policy_statements

first_policy = {
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
        "s3:PutObject",
        "s3:PutObjectVersionAcl",
        "s3:PutObjectVersionTagging",
    ],
    "Resource": "*",
  }]
}

second_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
          "s3:PutObjectVersionAcl",
          "s3:PutObjectVersionTagging",
      ],
      "Resource": "*",
    }
  ]
}

print(collapse_policy_statements(first_policy, second_policy))
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": [
#           "s3:PutObjectVersionAcl",
#           "s3:PutObjectVersionTagging",
#           "s3:PutObject",
#       ],
#       "Resource": "*",
#     }
#   ]
# }
```

Note how any duplicates are removed, and because all the Actions related to the same Resource, they were merged. If the Resource differs, the merge would not take place. Effect, Principals and Conditions are also included in the comparison: if any of those differ, the statement is not merged.

### Generate policies

This is a simple policy-generation API that generates policies for a particular service based on an access level (read, write, list, tagging or permissions management).

```python

from aws_iam_utils.generator import generate_read_only_policy_for_service

print(json.dumps(generate_read_only_policy_for_service('kinesis')))
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": [
#         "kinesis:DescribeLimits",
#         "kinesis:DescribeStream",
#         "kinesis:DescribeStreamConsumer",
#         "kinesis:DescribeStreamConsumer",
#         "kinesis:DescribeStreamSummary",
#         "kinesis:GetRecords",
#         "kinesis:GetShardIterator",
#         "kinesis:ListShards",
#         "kinesis:ListStreamConsumers",
#         "kinesis:ListStreams",
#         "kinesis:ListTagsForStream",
#         "kinesis:SubscribeToShard",
#         "kinesis:SubscribeToShard"
#       ],
#       "Resource": "*"
#     }
#   ]
# }
```

There is also `generate_read_write_policy_for_service` and `generate_list_only_policy_for_service`, and `generate_full_policy_for_service`.

# Documentation

Coming soon. In the meantime each function already has documentation - check the sources. For example usage, see the tests.

# Licence

MIT
