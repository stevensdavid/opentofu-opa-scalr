package aws.controls.iam

import data.aws.utils as aws_utils
import data.utils

import rego.v1

evaluate_iam_1(plan) := {violation |
	some [statement, address] in all_iam_statements(plan)

	statement_allows_action(statement, "*")
	statement_allows_resource(statement, "*")

	violation := {
		"id": {"opa": "aws.controls.iam.1", "control_tower": "CT.IAM.PR.1"},
		"reason": "Require that an AWS Identity and Access Management (IAM) inline policy does not have a statement that includes \" * \" in the Action and Resource elements",
		"resource": address,
		"severity": "high",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsiam1",
	}
}

evaluate_iam_2(plan) := {violation |
	some [statement, address] in all_iam_statements(plan)
	statement_allows_wildcard_service_actions(statement)

	violation := {
		"id": {"opa": "aws.controls.iam.2", "control_tower": "CT.IAM.PR.3"},
		"reason": "Require that AWS Identity and Access Management (IAM) customer-managed policies do not have wildcard service actions",
		"severity": "low",
		"resource": address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsiam2",
	}
}

evaluate_iam_3(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, {
		"aws_iam_user_policy",
		"aws_iam_user_policies_exclusive",
		"aws_iam_user_policy_attachment",
		"aws_iam_user_policy_attachments_exclusive",
	})

	violation := {
		"id": {"opa": "aws.controls.iam.3", "control_tower": "CT.IAM.PR.4"},
		"reason": "Require that an AWS Identity and Access Management(IAM) user does not have an inline or managed policy attached",
		"resource": address,
		"severity": "low",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsiam3",
	}
}
