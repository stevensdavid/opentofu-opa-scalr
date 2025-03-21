package aws.controls.rds

import data.utils

evaluate_rds_1(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	not resource.configuration.multi_az
	standard_engine(resource.configuration.engine)

	violation := {
		"id": {"opa": "aws.controls.rds.1", "control_tower": "CT.RDS.PR.1"},
		"severity": "medium",
		"reason": "Require that an Amazon RDS database instance is configured with multiple Availability Zones",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds1",
	}
}

misconfigured_monitoring(resource) if {
	# The case of invalid monitoring intervals is handled by the Terraform provider,
	# and the provider defaults the field to 0. We only have to check the = 0 case
	# and missing roles.
	resource.configuration.monitoring_interval == 0
}

misconfigured_monitoring(resource) if {
	resource.configuration.monitoring_role_arn == ""
}

misconfigured_monitoring(resource) if {
	is_null(resource.configuration.monitoring_role_arn)
}

misconfigured_monitoring(resource) if not resource.configuration.monitoring_role_arn

evaluate_rds_2(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)
	misconfigured_monitoring(resource)

	violation := {
		"id": {"opa": "aws.controls.rds.2", "control_tower": "CT.RDS.PR.2"},
		"severity": "low",
		"reason": "Require an Amazon RDS database instance or cluster to have enhanced monitoring configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds2",
	}
}

evaluate_rds_3(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	utils.null_or_false(resource.configuration.deletion_protection)

	violation := {
		"id": {"opa": "aws.controls.rds.3", "control_tower": "CT.RDS.PR.3"},
		"severity": "low",
		"reason": "Require an Amazon RDS cluster to have deletion protection configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds3",
	}
}

evaluate_rds_4(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	resource.configuration.engine in {"aurora-mysql", "aurora-postgresql"}
	utils.null_or_false(resource.configuration.iam_database_authentication_enabled)

	violation := {
		"id": {"opa": "aws.controls.rds.4", "control_tower": "CT.RDS.PR.4"},
		"severity": "medium",
		"reason": "Require an Amazon RDS database cluster to have AWS IAM database authentication configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds4",
	}
}

evaluate_rds_5(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)
	not resource.configuration.auto_minor_version_upgrade

	violation := {
		"id": {"opa": "aws.controls.rds.5", "control_tower": "CT.RDS.PR.5"},
		"severity": "high",
		"reason": "Require an Amazon RDS database instance to have minor version upgrades configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds5",
	}
}

evaluate_rds_6(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	backtrackable(resource.configuration)
	utils.falsy(resource.configuration.backtrack_window)

	violation := {
		"id": {"opa": "aws.controls.rds.6", "control_tower": "CT.RDS.PR.6"},
		"severity": "medium",
		"reason": "Require an Amazon RDS database cluster to have backtracking configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds6",
	}
}

evaluate_rds_7(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	resource.configuration.engine in {"mysql", "mariadb", "postgres"}
	utils.null_or_false(resource.configuration.iam_database_authentication_enabled)

	violation := {
		"id": {"opa": "aws.controls.rds.7", "control_tower": "CT.RDS.PR.7"},
		"severity": "medium",
		"reason": "Require Amazon RDS database instances to have IAM authentication configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds7",
	}
}

evaluate_rds_8(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)
	invalid_backup_retention_period(resource.configuration)
	violation := {
		"id": {"opa": "aws.controls.rds.8", "control_tower": "CT.RDS.PR.8"},
		"severity": "medium",
		"reason": "Require an Amazon RDS database instance to have automatic backups configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds8",
	}
}

evaluate_rds_9(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	resource.configuration.engine in {"aurora-mysql", "aurora-postgresql"}
	utils.null_or_false(resource.configuration.copy_tags_to_snapshot)

	violation := {
		"id": {"opa": "aws.controls.rds.9", "control_tower": "CT.RDS.PR.9"},
		"severity": "low",
		"reason": "Require an Amazon RDS database cluster to copy tags to snapshots",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds9",
	}
}

evaluate_rds_10(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)
	utils.null_or_false(resource.configuration.copy_tags_to_snapshot)

	violation := {
		"id": {"opa": "aws.controls.rds.10", "control_tower": "CT.RDS.PR.10"},
		"reason": "Require an Amazon RDS database instance to copy tags to snapshots",
		"severity": "low",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds10",
	}
}

evaluate_rds_11(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")

	standard_engine(resource.configuration.engine)
	not resource.configuration.db_subnet_group_name
	violation := {
		"id": {"opa": "aws.controls.rds.11", "control_tower": "CT.RDS.PR.11"},
		"severity": "high",
		"reason": "Require an Amazon RDS database instance to have a VPC configuration",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds11",
	}
}

evaluate_rds_12(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_event_subscription")
	resource.configuration.source_type == "db-cluster"
	not valid_event_subscription(resource)
	violation := {
		"id": {"opa": "aws.controls.rds.12", "control_tower": "CT.RDS.PR.12"},
		"reason": "Require an Amazon RDS event subscription to have critical cluster events configured",
		"severity": "low",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds12",
	}
}

evaluate_rds_13(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)
	utils.null_or_false(resource.configuration.deletion_protection)

	violation := {
		"id": {"opa": "aws.controls.rds.13", "control_tower": "CT.RDS.PR.13"},
		"severity": "low",
		"reason": "Require any Amazon RDS instance to have deletion protection configured",
		"resource": resource.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds13",
	}
}

evaluate_rds_14(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	standard_engine(instance.configuration.engine)
	not valid_log_configuration(instance)

	violation := {
		"id": {"opa": "aws.controls.rds.14", "control_tower": "CT.RDS.PR.14"},
		"reason": "Require an Amazon RDS database instance to export logs to Amazon CloudWatch Logs by means of the EnableCloudwatchLogsExports property",
		"resource": instance.address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds14",
	}
}
