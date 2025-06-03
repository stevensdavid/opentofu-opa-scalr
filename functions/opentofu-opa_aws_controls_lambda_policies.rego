package aws.controls.lambda

import data.aws.utils as aws_utils
import data.utils

import rego.v1

evaluate_lambda_1(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_lambda_permission")
	public_access(configuration)

	violation := {
		"id": {"opa": "aws.controls.lambda.1", "control_tower": "CT.LAMBDA.PR.2"},
		"reason": "Require AWS Lambda function policies to prohibit public access",
		"resource": address,
		"severity": "critical",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolslambda1",
	}
}

evaluate_lambda_2(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_lambda_function")
	not valid_vpc_config(configuration)

	violation := {
		"id": {"opa": "aws.controls.lambda.2", "control_tower": "CT.LAMBDA.PR.3"},
		"reason": "Require an AWS Lambda function to be in a customer-managed Amazon Virtual Private Cloud (VPC)",
		"resource": address,
		"severity": "low",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolslambda2",
	}
}

evaluate_lambda_3(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_lambda_layer_version_permission")
	configuration.principal = "*"
	utils.falsy(configuration.organization_id)

	violation := {
		"id": {"opa": "aws.controls.lambda.3", "control_tower": "CT.LAMBDA.PR.4"},
		"reason": "Require an AWS Lambda layer permission to grant access to an AWS organization or specific AWS account",
		"severity": "critical",
		"resource": address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolslambda3",
	}
}

evaluate_lambda_4(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_lambda_function_url")
	configuration.authorization_type != "AWS_IAM"

	violation := {
		"id": {"opa": "aws.controls.lambda.4"},
		"reason": "Require an AWS Lambda function URL to use AWS IAM-based authentication",
		"resource": address,
		"severity": "critical",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolslambda4",
	}
}

evaluate_lambda_5(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_lambda_function_url")
	some cors in configuration.cors
	some origin in cors.allow_origins
	origin in {"*", "https://*", "http://*"}

	violation := {
		"id": {"opa": "aws.controls.lambda.5", "control_tower": "CT.LAMBDA.PR.5"},
		"reason": "Require an AWS Lambda function URL CORS policy to restrict access to specific origins",
		"resource": address,
		"severity": "high",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolslambda5",
	}
}
