package aws.utils

import rego.v1

matches_account_id(s) := regex.match(`^\d{12}$`, s)

matches_iam_principal(s) := regex.match(`^arn:aws[a-z0-9\-]*:iam::\d{12}:.+`, s)
