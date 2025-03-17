package aws.controls.rds

import data.utils

evaluate_rds_1(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	not resource.configuration.multi_az
	standard_engine(resource.configuration.engine)

	violation := {
		"id": {"opa": "aws.controls.rds.1", "control_tower": "CT.RDS.PR.1"},
		"reason": "Require that an Amazon RDS database instance is configured with multiple Availability Zones",
		"resource": resource.address,
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
		"reason": "Require an Amazon RDS database instance or cluster to have enhanced monitoring configured",
		"resource": resource.address,
	}
}

evaluate_rds_3(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	utils.null_or_false(resource.configuration.deletion_protection)

	violation := {
		"id": {"opa": "aws.controls.rds.3", "control_tower": "CT.RDS.PR.3"},
		"reason": "Require an Amazon RDS cluster to have deletion protection configured",
		"resource": resource.address,
	}
}

evaluate_rds_4(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	resource.configuration.engine in {"aurora-mysql", "aurora-postgresql"}
	utils.null_or_false(resource.configuration.iam_database_authentication_enabled)

	violation := {
		"id": {"opa": "aws.controls.rds.4", "control_tower": "CT.RDS.PR.4"},
		"reason": "Require an Amazon RDS database cluster to have AWS IAM database authentication configured",
		"resource": resource.address,
	}
}

evaluate_rds_5(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)
	not resource.configuration.auto_minor_version_upgrade

	violation := {
		"id": {"opa": "aws.controls.rds.5", "control_tower": "CT.RDS.PR.5"},
		"reason": "Require an Amazon RDS database instance to have minor version upgrades configured",
		"resource": resource.address,
	}
}

evaluate_rds_6(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	backtrackable(resource.configuration)
	utils.falsy(resource.configuration.backtrack_window)

	violation := {
		"id": {"opa": "aws.controls.rds.6", "control_tower": "CT.RDS.PR.6"},
		"reason": "Require an Amazon RDS database cluster to have backtracking configured",
		"resource": resource.address,
	}
}

evaluate_rds_7(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	resource.configuration.engine in {"mysql", "mariadb", "postgres"}
	utils.null_or_false(resource.configuration.iam_database_authentication_enabled)

	violation := {
		"id": {"opa": "aws.controls.rds.7", "control_tower": "CT.RDS.PR.7"},
		"reason": "Require Amazon RDS database instances to have IAM authentication configured",
		"resource": resource.address,
	}
}

evaluate_rds_8(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)
	invalid_backup_retention_period(resource.configuration)
	violation := {
		"id": {"opa": "aws.controls.rds.8", "control_tower": "CT.RDS.PR.8"},
		"reason": "Require an Amazon RDS database instance to have automatic backups configured",
		"resource": resource.address,
	}
}

evaluate_rds_9(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	resource.configuration.engine in {"aurora-mysql", "aurora-postgresql"}
	utils.null_or_false(resource.configuration.copy_tags_to_snapshot)

	violation := {
		"id": {"opa": "aws.controls.rds.9", "control_tower": "CT.RDS.PR.9"},
		"reason": "Require an Amazon RDS database cluster to copy tags to snapshots",
		"resource": resource.address,
	}
}
