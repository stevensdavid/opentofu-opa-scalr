package aws.controls_test

import rego.v1

import data.aws.controls

test_evaluate_all_includes_all_rules if {
	every service in object.keys(controls.mocks) {
		every rule_id in object.keys(controls.mocks[service]) {
			opa_rule_id := sprintf("aws.controls.%s.%s", [service, rule_id])
			denies := controls.evaluate_all(controls.mocks[service][rule_id].fail)
			some deny in denies
			deny.id.opa == opa_rule_id

			permits := controls.evaluate_all(controls.mocks[service][rule_id].pass)
			every unrelated_deny in permits {
				unrelated_deny.id.opa != opa_rule_id
			}
		}
	}
}
