package aws.controls.iam

import data.aws.utils as aws_utils
import data.utils
import rego.v1

all_iam_statements(plan) := union({
	{[statement, address] |
		some resource in plan.resource_changes
		some action in resource.change.actions
		action in {"create", "update"}
		resource.type in {"aws_iam_group_policy", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}
		policy := json.unmarshal(resource.change.after.policy)
		some statement in policy.Statement
		address := resource.address
	},
	{[statement, address] |
		some resource in plan.resource_changes
		some action in resource.change.actions
		action in {"create", "update"}
		resource.type == "aws_iam_role"
		some inline_policy in resource.change.after.inline_policy
		policy := json.unmarshal(inline_policy.policy)
		some statement in policy.Statement
		address := resource.address
	},
	{[statement, address] |
		some resource in walk(plan.prior_state.values.root_module)
		resource.mode == "data"
		resource.type == "aws_iam_policy_document"
		some hcl_statement in resource.values.statement
		statement := {
			"Action": hcl_statement.actions,
			"Effect": hcl_statement.effect,
			"Resource": hcl_statement.resources,
			"Condition": hcl_statement.condition,
			"Principal": hcl_statement.principals,
			"Sid": hcl_statement.sid,
			"NotAction": hcl_statement.not_actions,
			"NotResource": hcl_statement.not_resources,
			"NotPrincipal": hcl_statement.not_principals,
		}
		address := resource.address
	},
})

statement_allows_action(statement, action) if action in statement.Action

statement_allows_action(statement, action) if statement.Action == action

statement_allows_resource(statement, resource) if resource in statement.Resource

statement_allows_resource(statement, resource) if resource == statement.Resource

statement_allows_wildcard_service_actions(statement) if {
	statement.Effect == "Allow"
	some action in statement.Action
	regex.match(`^[\w]*[:]*\*$`, action)
}

statement_allows_wildcard_service_actions(statement) if {
	statement.Effect == "Allow"
	regex.match(`^[\w]*[:]*\*$`, statement.Action)
}

statement_allows_wildcard_service_actions(statement) if {
	statement.Effect == "Allow"
	not utils.falsy(statement.NotAction)
}
