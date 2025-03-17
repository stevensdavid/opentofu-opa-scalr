package aws.controls

import data.aws.controls.ecs
import data.aws.controls.rds
import rego.v1

evaluate_all(plan) := union({ecs.evaluate(plan), rds.evaluate(plan)})
