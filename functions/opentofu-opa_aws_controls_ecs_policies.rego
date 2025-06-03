package aws.controls.ecs

import data.utils

import rego.v1

evaluate_ecs_1(plan) := {rule |
	some service in utils.resources(plan, "aws_ecs_service")
	service.configuration.launch_type == "FARGATE"
	service.configuration.platform_version != "LATEST"
	rule := {
		"id": {"control_tower": "CT.ECS.PR.1", "fsbp": "ECS.10", "opa": "aws.controls.ecs.1"},
		"severity": "medium",
		"reason": "Require Amazon ECS Fargate Services to run on the latest Fargate platform version",
		"resource": service.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs1",
	}
}

evaluate_ecs_2(plan) := {rule |
	some cluster in utils.resources(plan, "aws_ecs_cluster")
	cluster_insights_is_disabled(cluster.configuration)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.2", "fsbp": "ECS.12", "opa": "aws.controls.ecs.2"},
		"severity": "medium",
		"reason": "Require any Amazon ECS cluster to have container insights activated",
		"resource": cluster.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs2",
	}
}

evaluate_ecs_3(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(task_definition.configuration.container_definitions)
	is_root_user(container)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.3", "opa": "aws.controls.ecs.3"},
		"severity": "high",
		"resource": task_definition.address,
		"reason": "Require any Amazon ECS task definition to specify a user that is not the root",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs3",
	}
}

evaluate_ecs_4(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	task_doesnt_use_awsvpc(task_definition)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.4", "opa": "aws.controls.ecs.4"},
		"severity": "high",
		"reason": "Require Amazon ECS tasks to use 'awsvpc' networking mode",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs4",
	}
}

evaluate_ecs_5(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(task_definition.configuration.container_definitions)
	not container.logConfiguration
	rule := {
		"id": {"control_tower": "CT.ECS.PR.5", "fsbp": "ECS.9", "opa": "aws.controls.ecs.5"},
		"severity": "high",
		"reason": "Require an active Amazon ECS task definition to have a logging configuration",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs5",
	}
}

evaluate_ecs_6(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(task_definition.configuration.container_definitions)
	not container.readonlyRootFilesystem
	rule := {
		"id": {"control_tower": "CT.ECS.PR.6", "fsbp": "ECS.5", "opa": "aws.controls.ecs.6"},
		"severity": "high",
		"reason": "Require Amazon ECS containers to allow read-only access to the root filesystem",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs6",
	}
}

evaluate_ecs_7(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(task_definition.configuration.container_definitions)
	not container.memory
	rule := {
		"id": {"control_tower": "CT.ECS.PR.7", "opa": "aws.controls.ecs.7"},
		"severity": "high",
		"reason": "Require an Amazon ECS task definition to have a specific memory usage limit",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs7",
	}
}

evaluate_ecs_8(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	task_definition.configuration.network_mode == "host"
	some container in json.unmarshal(task_definition.configuration.container_definitions)
	not container.privileged
	is_root_user(container)
	rule := {
		"id": {"control_tower": "CT.ECS.PR.8", "fsbp": "ECS.1", "opa": "aws.controls.ecs.8"},
		"severity": "high",
		"reason": "Require Amazon ECS task definitions to have secure networking modes and user definitions",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs8",
	}
}

evaluate_ecs_9(plan) := {rule |
	some service in utils.resources(plan, "aws_ecs_service")
	some network in service.configuration.network_configuration
	network.assign_public_ip == true
	rule := {
		"id": {"control_tower": "CT.ECS.PR.9", "fsbp": "ECS.2", "opa": "aws.controls.ecs.9"},
		"severity": "high",
		"reason": "Require Amazon ECS services not to assign public IP addresses automatically",
		"resource": service.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs9",
	}
}

evaluate_ecs_10(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	task_definition.configuration.pid_mode == "host"
	rule := {
		"id": {"control_tower": "CT.ECS.PR.10", "fsbp": "ECS.3", "opa": "aws.controls.ecs.10"},
		"severity": "high",
		"reason": "Require that Amazon ECS task definitions do not share the host's process namespace",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs10",
	}
}

evaluate_ecs_11(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(task_definition.configuration.container_definitions)
	container.privileged
	rule := {
		"id": {"control_tower": "CT.ECS.PR.11", "fsbp": "ECS.4", "opa": "aws.controls.ecs.11"},
		"severity": "high",
		"reason": "Require an Amazon ECS container to run as non-privileged",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs11",
	}
}

evaluate_ecs_12(plan) := {rule |
	some task_definition in utils.resources(plan, "aws_ecs_task_definition")
	some container in json.unmarshal(task_definition.configuration.container_definitions)
	some variable in container.environment
	variable.name in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"}
	rule := {
		"id": {"control_tower": "CT.ECS.PR.12", "fsbp": "ECS.8", "opa": "aws.controls.ecs.12"},
		"severity": "high",
		"reason": "Require that Amazon ECS task definitions do not pass secrets as container environment variables",
		"resource": task_definition.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs12",
	}
}

evaluate_ecs_13(plan) := {rule |
	some task_set in utils.resources(plan, "aws_ecs_task_set")
	some network in task_set.configuration.network_configuration
	network.assign_public_ip == true
	rule := {
		"id": {"opa": "aws.controls.ecs.13", "fsbp": "ECS.16"},
		"reason": "Require that ECS task sets do not automatically assign public IP addresses",
		"severity": "high",
		"resource": task_set.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsecs13",
	}
}
