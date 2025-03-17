package aws.controls.ecs_test

import rego.v1

import data.aws.controls
import data.aws.controls.ecs

test_evaluate_includes_all_rules if {
	every rule_id in object.keys(controls.mocks.ecs) {
		opa_rule_id := sprintf("aws.controls.ecs.%s", [rule_id])
		denies := ecs.evaluate(controls.mocks.ecs[rule_id].fail)
		some deny in denies
		deny.id.opa == opa_rule_id

		permits := ecs.evaluate(controls.mocks.ecs[rule_id].pass)
		every unrelated_deny in permits {
			unrelated_deny.id.opa != opa_rule_id
		}
	}
}
