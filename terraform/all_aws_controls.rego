package terraform

import rego.v1

import data.aws.controls
import input.tfplan as tfplan

deny[reason] if {
	errors := controls.evaluate_all(tfplan)
	some error in errors
	reason := sprintf("[%s] %s fails policy: %s (Docs: %s)", [error.severity, error.resource, error.reason, error.docs])
}