package aws.controls.ecs

import data.utils

import rego.v1

fargate_uses_latest_version(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_service")
	resource.configuration.launch_type == "FARGATE"
	resource.configuration.platform_version != "LATEST"
	rule := {
		"id": {"control_tower": "CT.ECS.PR.1", "fsbp": "ECS.10", "opa": "aws.controls.ecs.1"},
		"severity": "medium",
		"reason": "Require Amazon ECS Fargate Services to run on the latest Fargate platform version",
		"resource": resource.address,
	}
}

clusters_enable_container_insights(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_cluster")
	cluster_insights_is_disabled(resource.configuration)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.2", "fsbp": "ECS.12", "opa": "aws.controls.ecs.2"},
		"severity": "medium",
		"reason": "ECS clusters should enable container insights",
		"resource": resource.address,
	}
}

task_definitions_should_not_run_as_root(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(resource.configuration.container_definitions)
	is_root_user(container)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.3", "opa": "aws.controls.ecs.3"},
		"reason": "Task definitions should not run as root",
	}
}

tasks_use_awsvpc_network_mode(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	task_doesnt_use_awsvpc(resource)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.4", "opa": "aws.controls.ecs.4"},
		"reason": "Tasks should use 'awsvpc' networking mode",
		"resource": resource.address,
	}
}

task_containers_have_logging_configurations(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(resource.configuration.container_definitions)
	not container.logConfiguration
	rule := {
		"id": {"control_tower": "CT.ECS.PR.5", "fsbp": "ECS.9", "opa": "aws.controls.ecs.5"},
		"severity": "high",
		"reason": "Task containers must have a logging configuration",
		"resource": resource.address,
	}
}

task_containers_have_read_only_root_filesystems(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(resource.configuration.container_definitions)
	not container.readonlyRootFilesystem
	rule := {
		"id": {"control_tower": "CT.ECS.PR.6", "fsbp": "ECS.5", "opa": "aws.controls.ecs.6"},
		"severity": "high",
		"reason": "Task containers should have read-only root filesystems",
		"resource": resource.address,
	}
}

task_containers_specify_memory_usage_limits(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(resource.configuration.container_definitions)
	not container.memory
	rule := {
		"id": {"control_tower": "CT.ECS.PR.7", "opa": "aws.controls.ecs.7"},
		"reason": "Task containers should specify memory usage limits",
		"resource": resource.address,
	}
}

task_definitions_have_secure_networking_modes_and_user_definitions(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	resource.configuration.network_mode == "host"
	some container in json.unmarshal(resource.configuration.container_definitions)
	not container.privileged
	is_root_user(container)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.8", "fsbp": "ECS.1", "opa": "aws.controls.ecs.8"},
		"severity": "high",
		"reason": "Task definitions should have secure networking modes and user definitions",
		"resource": resource.address,
	}
}

services_should_not_have_public_ips(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_service")
	some network in resource.configuration.network_configuration
	network.assign_public_ip == true
	rule := {
		"id": {"control_tower": "CT.ECS.PR.9", "fsbp": "ECS.2", "opa": "aws.controls.ecs.9"},
		"severity": "high",
		"reason": "Public IP should not be assigned to ECS service",
		"resource": resource.address,
	}
}

tasks_should_not_use_hosts_process_namespace(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	resource.configuration.pid_mode == "host"
	rule := {
		"id": {"control_tower": "CT.ECS.PR.10", "fsbp": "ECS.3", "opa": "aws.controls.ecs.10"},
		"severity": "high",
		"reason": "ECS tasks should not use the host's process namespace",
		"resource": resource.address,
	}
}

tasks_should_run_as_non_privileged(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(resource.configuration.container_definitions)
	container.privileged
	rule := {
		"id": {"control_tower": "CT.ECS.PR.11", "fsbp": "ECS.4", "opa": "aws.controls.ecs.11"},
		"severity": "high",
		"reason": "ECS tasks should run as non-privileged",
		"resource": resource.address,
	}
}

tasks_do_not_pass_secrets_in_environment_variables(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(resource.configuration.container_definitions)
	some variable in container.environment
	variable.name in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"}
	rule := {
		"id": {"control_tower": "CT.ECS.PR.12", "fsbp": "ECS.8", "opa": "aws.controls.ecs.12"},
		"severity": "high",
		"reason": "ECS tasks do not pass secrets as container environment variables",
		"resource": resource.address,
	}
}

task_sets_should_not_have_public_ips(plan) := {rule |
	some resource in utils.resources(plan, "aws_ecs_task_set")
	some network in resource.configuration.network_configuration
	network.assign_public_ip == true
	rule := {
		"id": {"opa": "aws.controls.ecs.13", "fsbp": "ECS.16"},
		"reason": "ECS task sets should not automatically assign public IP addresses",
		"severity": "high",
		"resource": resource.address,
	}
}
