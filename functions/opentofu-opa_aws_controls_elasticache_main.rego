package aws.controls.elasticache

import rego.v1

evaluate(plan) := union({evaluate_elasticache_1(plan), evaluate_elasticache_2(plan)})
