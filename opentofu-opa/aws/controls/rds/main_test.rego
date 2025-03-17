package aws.controls.rds_test

import rego.v1

import data.aws.controls
import data.aws.controls.rds

test_evaluate_includes_all_rules if {
	every rule_id in object.keys(controls.mocks.rds) {
		opa_rule_id := sprintf("aws.controls.rds.%s", [rule_id])
		denies := rds.evaluate(controls.mocks.rds[rule_id].fail)
		some deny in denies
		deny.id.opa == opa_rule_id

		permits := rds.evaluate(controls.mocks.rds[rule_id].pass)
		every unrelated_deny in permits {
			unrelated_deny.id.opa != opa_rule_id
		}
	}
}
