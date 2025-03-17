package aws.controls.ecs

import rego.v1

evaluate(plan) := union({
	fargate_uses_latest_version(plan),
	clusters_enable_container_insights(plan),
	task_definitions_should_not_run_as_root(plan),
	tasks_use_awsvpc_network_mode(plan),
	task_containers_have_logging_configurations(plan),
	task_containers_have_read_only_root_filesystems(plan),
	task_containers_specify_memory_usage_limits(plan),
	task_definitions_have_secure_networking_modes_and_user_definitions(plan),
	services_should_not_have_public_ips(plan),
	tasks_should_not_use_hosts_process_namespace(plan),
	tasks_should_run_as_non_privileged(plan),
	tasks_do_not_pass_secrets_in_environment_variables(plan),
	task_sets_should_not_have_public_ips(plan),
})
