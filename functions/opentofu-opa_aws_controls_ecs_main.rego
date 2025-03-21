package aws.controls.ecs

import rego.v1

evaluate(plan) := union({
	evaluate_ecs_1(plan),
	evaluate_ecs_2(plan),
	evaluate_ecs_3(plan),
	evaluate_ecs_4(plan),
	evaluate_ecs_5(plan),
	evaluate_ecs_6(plan),
	evaluate_ecs_7(plan),
	evaluate_ecs_8(plan),
	evaluate_ecs_9(plan),
	evaluate_ecs_10(plan),
	evaluate_ecs_11(plan),
	evaluate_ecs_12(plan),
	evaluate_ecs_13(plan),
})
