package aws.controls.rds

import data.utils

evaluate_rds_1(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	not instance.configuration.multi_az
	standard_engine(instance.configuration.engine)

	violation := {
		"id": {"opa": "aws.controls.rds.1", "control_tower": "CT.RDS.PR.1"},
		"severity": "medium",
		"reason": "Require that an Amazon RDS database instance is configured with multiple Availability Zones",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds1",
	}
}

evaluate_rds_2(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	standard_engine(instance.configuration.engine)
	misconfigured_monitoring(instance)

	violation := {
		"id": {"opa": "aws.controls.rds.2", "control_tower": "CT.RDS.PR.2"},
		"severity": "low",
		"reason": "Require an Amazon RDS database instance or cluster to have enhanced monitoring configured",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds2",
	}
}

evaluate_rds_3(plan) := {violation |
	some cluster in utils.resources(plan, "aws_rds_cluster")
	utils.null_or_false(cluster.configuration.deletion_protection)

	violation := {
		"id": {"opa": "aws.controls.rds.3", "control_tower": "CT.RDS.PR.3"},
		"severity": "low",
		"reason": "Require an Amazon RDS cluster to have deletion protection configured",
		"resource": cluster.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds3",
	}
}

evaluate_rds_4(plan) := {violation |
	some cluster in utils.resources(plan, "aws_rds_cluster")
	cluster.configuration.engine in {"aurora-mysql", "aurora-postgresql"}
	utils.null_or_false(cluster.configuration.iam_database_authentication_enabled)

	violation := {
		"id": {"opa": "aws.controls.rds.4", "control_tower": "CT.RDS.PR.4"},
		"severity": "medium",
		"reason": "Require an Amazon RDS database cluster to have AWS IAM database authentication configured",
		"resource": cluster.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds4",
	}
}

evaluate_rds_5(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	standard_engine(instance.configuration.engine)
	not instance.configuration.auto_minor_version_upgrade

	violation := {
		"id": {"opa": "aws.controls.rds.5", "control_tower": "CT.RDS.PR.5"},
		"severity": "high",
		"reason": "Require an Amazon RDS database instance to have minor version upgrades configured",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds5",
	}
}

evaluate_rds_6(plan) := {violation |
	some cluster in utils.resources(plan, "aws_rds_cluster")
	backtrackable(cluster.configuration)
	utils.falsy(cluster.configuration.backtrack_window)

	violation := {
		"id": {"opa": "aws.controls.rds.6", "control_tower": "CT.RDS.PR.6"},
		"severity": "medium",
		"reason": "Require an Amazon RDS database cluster to have backtracking configured",
		"resource": cluster.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds6",
	}
}

evaluate_rds_7(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	instance.configuration.engine in {"mysql", "mariadb", "postgres"}
	utils.null_or_false(instance.configuration.iam_database_authentication_enabled)

	violation := {
		"id": {"opa": "aws.controls.rds.7", "control_tower": "CT.RDS.PR.7"},
		"severity": "medium",
		"reason": "Require Amazon RDS database instances to have IAM authentication configured",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds7",
	}
}

evaluate_rds_8(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	standard_engine(instance.configuration.engine)
	invalid_backup_retention_period(instance.configuration)
	violation := {
		"id": {"opa": "aws.controls.rds.8", "control_tower": "CT.RDS.PR.8"},
		"severity": "medium",
		"reason": "Require an Amazon RDS database instance to have automatic backups configured",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds8",
	}
}

evaluate_rds_9(plan) := {violation |
	some cluster in utils.resources(plan, "aws_rds_cluster")
	cluster.configuration.engine in {"aurora-mysql", "aurora-postgresql"}
	utils.null_or_false(cluster.configuration.copy_tags_to_snapshot)

	violation := {
		"id": {"opa": "aws.controls.rds.9", "control_tower": "CT.RDS.PR.9"},
		"severity": "low",
		"reason": "Require an Amazon RDS database cluster to copy tags to snapshots",
		"resource": cluster.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds9",
	}
}

evaluate_rds_10(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	standard_engine(instance.configuration.engine)
	utils.null_or_false(instance.configuration.copy_tags_to_snapshot)

	violation := {
		"id": {"opa": "aws.controls.rds.10", "control_tower": "CT.RDS.PR.10"},
		"reason": "Require an Amazon RDS database instance to copy tags to snapshots",
		"severity": "low",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds10",
	}
}

evaluate_rds_11(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")

	standard_engine(instance.configuration.engine)
	not instance.configuration.db_subnet_group_name
	violation := {
		"id": {"opa": "aws.controls.rds.11", "control_tower": "CT.RDS.PR.11"},
		"severity": "high",
		"reason": "Require an Amazon RDS database instance to have a VPC configuration",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds11",
	}
}

evaluate_rds_12(plan) := {violation |
	some subscription in utils.resources(plan, "aws_db_event_subscription")
	subscription.configuration.source_type == "db-cluster"
	not valid_event_subscription(subscription)
	violation := {
		"id": {"opa": "aws.controls.rds.12", "control_tower": "CT.RDS.PR.12"},
		"reason": "Require an Amazon RDS event subscription to have critical cluster events configured",
		"severity": "low",
		"resource": subscription.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds12",
	}
}

evaluate_rds_13(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	standard_engine(instance.configuration.engine)
	utils.null_or_false(instance.configuration.deletion_protection)

	violation := {
		"id": {"opa": "aws.controls.rds.13", "control_tower": "CT.RDS.PR.13"},
		"severity": "low",
		"reason": "Require any Amazon RDS instance to have deletion protection configured",
		"resource": instance.address,
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

evaluate_rds_15(plan) := {violation |
	some cluster in utils.resources(plan, "aws_rds_cluster")
	utils.falsy(cluster.configuration.replication_source_identifier)
	not cluster.configuration.storage_encrypted

	violation := {
		"id": {"opa": "aws.controls.rds.15", "control_tower": "CT.RDS.PR.16"},
		"reason": "Require an Amazon RDS database cluster to have encryption at rest configured",
		"resource": cluster.address,
		"severity": "high",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds15",
	}
}

evaluate_rds_16(plan) := {violation |
	some subscription in utils.resources(plan, "aws_db_event_subscription")
	subscription.configuration.source_type == "db-instance"
	not valid_event_subscription(subscription)

	violation := {
		"id": {"opa": "aws.controls.rds.16", "control_tower": "CT.RDS.PR.17"},
		"reason": "Require an Amazon RDS event notification subscription to have critical database instance events configured",
		"resource": subscription.address,
		"severity": "low",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds16",
	}
}

evaluate_rds_17(plan) := {violation |
	some subscription in utils.resources(plan, "aws_db_event_subscription")
	subscription.configuration.source_type == "db-parameter-group"
	not valid_event_subscription(subscription)

	violation := {
		"id": {"opa": "aws.controls.rds.17", "control_tower": "CT.RDS.PR.18"},
		"reason": "Require an Amazon RDS event notification subscription to have critical database parameter group events configured",
		"severity": "low",
		"resource": subscription.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds17",
	}
}

evaluate_rds_18(plan) := {violation |
	some subscription in utils.resources(plan, "aws_db_event_subscription")
	subscription.configuration.source_type = "db-security-group"
	not valid_event_subscription(subscription)

	violation := {
		"id": {"opa": "aws.controls.rds.18", "control_tower": "CT.RDS.PR.19"},
		"reason": "Require an Amazon RDS event notifications subscription to have critical database security group events configured",
		"severity": "low",
		"resource": subscription.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds18",
	}
}

evaluate_rds_19(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")

	standard_engine(instance.configuration.engine)
	uses_default_port(instance.configuration)

	violation := {
		"id": {"opa": "aws.controls.rds.19", "control_tower": "CT.RDS.PR.20"},
		"reason": "Require an Amazon RDS database instance not to use a database engine default port",
		"resource": instance.address,
		"severity": "low",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds19",
	}
}

evaluate_rds_20(plan) := {violation |
	some cluster in utils.resources(plan, "aws_rds_cluster")
	cluster.configuration.master_username in {"admin", "postgres"}

	violation := {
		"id": {"opa": "aws.controls.rds.20", "control_tower": "CT.RDS.PR.21"},
		"reason": "Require an Amazon RDS DB cluster to have a unique administrator username",
		"severity": "medium",
		"resource": cluster.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds20",
	}
}

evaluate_rds_21(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	instance.configuration.username in {"admin", "postgres"}

	violation := {
		"id": {"opa": "aws.controls.rds.21", "control_tower": "CT.RDS.PR.22"},
		"reason": "Require an Amazon RDS database instance to have a unique administrator username",
		"resource": instance.address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds21",
	}
}

evaluate_rds_22(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	instance.configuration.publicly_accessible
	violation := {
		"id": {"opa": "aws.controls.rds.22", "control_tower": "CT.RDS.PR.23"},
		"reason": "Require an Amazon RDS database instance to not be publicly accessible",
		"severity": "critical",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds22",
	}
}

evaluate_rds_23(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")

	not instance.configuration.storage_encrypted
	violation := {
		"id": {"opa": "aws.controls.rds.23", "control_tower": "CT.RDS.PR.24"},
		"reason": "Require an Amazon RDS database instance to have encryption at rest configured",
		"severity": "medium",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds23",
	}
}

evaluate_rds_24(plan) := {violation |
	some cluster in utils.resources(plan, "aws_rds_cluster")
	cluster.configuration.engine in {"aurora-mysql", "aurora-postgresql", "aurora", "mysql", "postgres"}
	not valid_log_configuration(cluster)

	violation := {
		"id": {"opa": "aws.controls.rds.24", "control_tower": "CT.RDS.PR.25"},
		"reason": "Require an Amazon RDS database cluster to export logs to Amazon CloudWatch Logs by means of the EnableCloudwatchLogsExports property",
		"resource": cluster.address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds24",
	}
}

evaluate_rds_25(plan) := {violation |
	some proxy in utils.resources(plan, "aws_db_proxy")
	utils.falsy(proxy.configuration.require_tls)

	violation := {
		"id": {"opa": "aws.controls.rds.25", "control_tower": "CT.RDS.PR.26"},
		"reason": "Require an Amazon Relational Database Service DB Proxy to require Transport Layer Security (TLS) connections",
		"resource": proxy.address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds25",
	}
}

evaluate_rds_26(plan) := {violation |
	some group in utils.resources(plan, "aws_rds_cluster_parameter_group")
	group.configuration.family in {"aurora-mysql", "aurora-postgresql", "mysql", "postgres"}

	not parameter_group_requires_tls(group.configuration.family, group.configuration.parameter)

	violation := {
		"id": {"opa": "aws.controls.rds.26"},
		"reason": "Require an Amazon Relational Database Service DB cluster parameter group to require Transport Layer Security (TLS) connections for supported engine types",
		"resource": group.address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds26",
	}
}

evaluate_rds_27(plan) := {violation |
	some group in utils.resources(plan, "aws_db_parameter_group")
	group.configuration.family != "mariadb10.4"
	[engine] := regex.find_n(`^([a-z]+)`, group.configuration.family, 1)

	not parameter_group_requires_tls(engine, group.configuration.parameter)

	violation := {
		"id": {"opa": "aws.controls.rds.27", "control_tower": "CT.RDS.PR.28"},
		"reason": "Require an Amazon Relational Database Service DB parameter group to require Transport Layer Security (TLS) connections for supported engine types",
		"resource": group.address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds27",
	}
}

evaluate_rds_28(plan) := {violation |
	some instance in utils.resources(plan, "aws_db_instance")
	standard_engine(instance.configuration.engine)
	invalid_kms_configuration(instance.configuration)

	violation := {
		"id": {"opa": "aws.controls.rds.28", "control_tower": "CT.RDS.PR.30"},
		"reason": "Require that an Amazon RDS database instance has encryption at rest configured to use a KMS key that you specify for supported engine types",
		"severity": "low",
		"resource": instance.address,
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsrds28",
	}
}
