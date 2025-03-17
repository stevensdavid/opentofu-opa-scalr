package aws.controls.rds_test

import data.aws.controls
import data.aws.controls.rds

test_evaluate_rds_1_valid_input if count(rds.evaluate_rds_1(controls.mocks.rds["1"].pass)) == 0

test_evaluate_rds_1_invalid_input if count(rds.evaluate_rds_1(controls.mocks.rds["1"].fail)) == 2

test_evaluate_rds_2_valid_input if count(rds.evaluate_rds_2(controls.mocks.rds["2"].pass)) == 0

# test_evaluate_rds_2_invalid_input if count(rds.evaluate_rds_2(controls.mocks.rds["2"].fail)) == 4
test_evaluate_rds_2_invalid_input if {
	result := rds.evaluate_rds_2(controls.mocks.rds["2"].fail)
	count(result) == 4
}

test_evaluate_rds_3_valid_input if count(rds.evaluate_rds_3(controls.mocks.rds["3"].pass)) == 0

test_evaluate_rds_3_invalid_input if count(rds.evaluate_rds_3(controls.mocks.rds["3"].fail)) == 2

test_evaluate_rds_4_valid_input if count(rds.evaluate_rds_4(controls.mocks.rds["4"].pass)) == 0

test_evaluate_rds_4_invalid_input if count(rds.evaluate_rds_4(controls.mocks.rds["4"].fail)) == 2

test_evaluate_rds_5_valid_input if count(rds.evaluate_rds_5(controls.mocks.rds["5"].pass)) == 0

test_evaluate_rds_5_invalid_input if count(rds.evaluate_rds_5(controls.mocks.rds["5"].fail)) == 1

test_evaluate_rds_6_valid_input if count(rds.evaluate_rds_6(controls.mocks.rds["6"].pass)) == 0

test_evaluate_rds_6_invalid_input if count(rds.evaluate_rds_6(controls.mocks.rds["6"].fail)) == 8

test_evaluate_rds_7_valid_input if count(rds.evaluate_rds_7(controls.mocks.rds["7"].pass)) == 0

test_evaluate_rds_7_invalid_input if count(rds.evaluate_rds_7(controls.mocks.rds["7"].fail)) == 2

test_evaluate_rds_8_valid_input if count(rds.evaluate_rds_8(controls.mocks.rds["8"].pass)) == 0

test_evaluate_rds_8_invalid_input if count(rds.evaluate_rds_8(controls.mocks.rds["8"].fail)) == 3

test_evaluate_rds_9_valid_input if count(rds.evaluate_rds_9(controls.mocks.rds["9"].pass)) == 0

test_evaluate_rds_9_invalid_input if count(rds.evaluate_rds_9(controls.mocks.rds["9"].fail)) == 2
