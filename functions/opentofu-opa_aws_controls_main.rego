package aws.controls

import data.aws.controls.ecs
import data.aws.controls.elasticache
import data.aws.controls.iam
import data.aws.controls.lambda
import data.aws.controls.rds
import rego.v1

evaluate_all(plan) := union({
	ecs.evaluate(plan),
	elasticache.evaluate(plan),
	iam.evaluate(plan),
	lambda.evaluate(plan),
	rds.evaluate(plan),
})
