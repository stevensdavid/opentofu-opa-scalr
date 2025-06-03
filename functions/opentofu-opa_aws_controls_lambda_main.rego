package aws.controls.lambda

import rego.v1

evaluate(plan) := union({evaluate_lambda_1(plan), evaluate_lambda_2(plan), evaluate_lambda_3(plan), evaluate_lambda_4(plan), evaluate_lambda_5(plan)})
