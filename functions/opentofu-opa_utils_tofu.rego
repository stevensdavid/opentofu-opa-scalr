package utils

import rego.v1

resources(plan, type) := array.concat(
	[{"address": result.address, "configuration": result.change.after} |
		is_string(type)
		some result in plan.resource_changes
		result.type == type
		some action in result.change.actions
		action in {"create", "update"}
	],
	[{"address": result.address, "configuration": result.change.after} |
		is_set(type)
		some result in plan.resource_changes
		result.type in type
		some action in result.change.actions
		action in {"create", "update"}
	],
)

null_or_false(null)

null_or_false(false)

falsy(null)

falsy(false)

falsy(0)

falsy("")

falsy([])

falsy({})

falsy(set())
