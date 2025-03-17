package aws.controls.ecs_test

import rego.v1

import data.aws.controls
import data.aws.controls.ecs

test_ecs_1_valid_input if count(ecs.fargate_uses_latest_version(controls.mocks.ecs["1"].pass)) == 0

test_ecs_1_invalid_input if ecs.fargate_uses_latest_version(controls.mocks.ecs["1"].fail)

test_ecs_2_valid_input if count(ecs.clusters_enable_container_insights(controls.mocks.ecs["2"].pass)) == 0

test_ecs_2_invalid_input if ecs.clusters_enable_container_insights(controls.mocks.ecs["2"].fail)

test_ecs_3_valid_input if count(ecs.task_definitions_should_not_run_as_root(controls.mocks.ecs["3"].pass)) == 0

test_ecs_3_invalid_input if ecs.task_definitions_should_not_run_as_root(controls.mocks.ecs["3"].fail)

test_ecs_4_valid_input if count(ecs.tasks_use_awsvpc_network_mode(controls.mocks.ecs["4"].pass)) == 0

test_ecs_4_invalid_input if ecs.tasks_use_awsvpc_network_mode(controls.mocks.ecs["4"].fail)

test_ecs_5_valid_input if count(ecs.task_containers_have_logging_configurations(controls.mocks.ecs["5"].pass)) == 0

test_ecs_5_invalid_input if ecs.task_containers_have_logging_configurations(controls.mocks.ecs["5"].fail)

test_ecs_6_valid_input if count(ecs.task_containers_have_read_only_root_filesystems(controls.mocks.ecs["6"].pass)) == 0

test_ecs_6_invalid_input if ecs.task_containers_have_read_only_root_filesystems(controls.mocks.ecs["6"].fail)

test_ecs_7_valid_input if count(ecs.task_containers_specify_memory_usage_limits(controls.mocks.ecs["7"].pass)) == 0

test_ecs_7_invalid_input if ecs.task_containers_specify_memory_usage_limits(controls.mocks.ecs["7"].fail)

test_ecs_8_valid_input if count(ecs.task_definitions_have_secure_networking_modes_and_user_definitions(controls.mocks.ecs["8"].pass)) == 0

test_ecs_8_invalid_input if ecs.task_definitions_have_secure_networking_modes_and_user_definitions(controls.mocks.ecs["8"].fail)

test_ecs_9_valid_input if count(ecs.services_should_not_have_public_ips(controls.mocks.ecs["9"].pass)) == 0

test_ecs_9_invalid_input if ecs.services_should_not_have_public_ips(controls.mocks.ecs["9"].fail)

test_ecs_10_valid_input if count(ecs.tasks_should_not_use_hosts_process_namespace(controls.mocks.ecs["10"].pass)) == 0

test_ecs_10_invalid_input if ecs.tasks_should_not_use_hosts_process_namespace(controls.mocks.ecs["10"].fail)

test_ecs_11_valid_input if count(ecs.tasks_should_run_as_non_privileged(controls.mocks.ecs["11"].pass)) == 0

test_ecs_11_invalid_input if ecs.tasks_should_run_as_non_privileged(controls.mocks.ecs["11"].fail)

test_ecs_12_valid_input if count(ecs.tasks_do_not_pass_secrets_in_environment_variables(controls.mocks.ecs["12"].pass)) == 0

test_ecs_12_invalid_input if ecs.tasks_do_not_pass_secrets_in_environment_variables(controls.mocks.ecs["12"].fail)

test_ecs_13_valid_input if count(ecs.task_sets_should_not_have_public_ips(controls.mocks.ecs["13"].pass)) == 0

test_ecs_13_invalid_input if ecs.task_sets_should_not_have_public_ips(controls.mocks.ecs["13"].fail)
