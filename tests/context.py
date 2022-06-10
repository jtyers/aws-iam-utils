# https://docs.python-guide.org/writing/structure/
import os
import sys

import aws_iam_utils  # noqa: F401

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
