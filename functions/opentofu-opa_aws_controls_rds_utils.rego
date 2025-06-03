package aws.controls.rds

import data.utils

standard_engine(engine) := engine in {"mariadb", "mysql", "oracle-ee", "oracle-ee-cdb", "oracle-se2", "oracle-se2-cdb", "postgres", "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web"}

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

backtrackable_engine_mode(null)

backtrackable_engine_mode("provisioned")

backtrackable_engine_mode("parallelquery")

parse_engine_version(version) := {"mysql": mysql_version, "aurora": aurora_version} if {
	pattern = `(\d+\.\d+).mysql_aurora\.(.+)`
	matches := regex.find_all_string_submatch_n(pattern, version, 1)[0]
	[_, mysql_version_raw, aurora_version] = matches

	# This is a bit of a hack to convert MySQL 8.0 to 8.0.0 so that semver can compare it
	mysql_version := sprintf("%s.0", [mysql_version_raw])
}

backtrackable_engine_version(version) if {
	versions = parse_engine_version(version)

	# If the version is less than 8.0, then it is backtrackable
	semver.compare(versions.mysql, "8.0.0") == -1
}

backtrackable_engine_version(version) if {
	versions = parse_engine_version(version)

	# If the version is 8.0, then it is backtrackable if the aurora version is less than 3.02.0
	semver.compare(versions.mysql, "8.0.0") == 0
	semver.compare(versions.aurora, "3.02.0") == -1
}

backtrackable(cluster) if {
	cluster.engine == "aurora-mysql"
	cluster.serverlessv2_scaling_configuration
	backtrackable_engine_version(cluster.engine_version)
}

backtrackable(cluster) if {
	cluster.engine == "aurora-mysql"
	utils.falsy(cluster.serverlessv2_scaling_configuration)
	backtrackable_engine_mode(cluster.engine_mode)
}

invalid_backup_retention_period(instance) if {
	instance.backup_retention_period < 7
}

invalid_backup_retention_period(instance) if {
	utils.falsy(instance.backup_retention_period)
}

invalid_backup_retention_period(instance) if {
	not instance.backup_retention_period
}

# Used in aws.controls.rds.12 and aws.controls.rds.16
event_categories("db-cluster") := ["maintenance", "failure"]

event_categories("db-instance") := ["maintenance", "failure", "configuration change"]

event_categories("db-parameter-group") := ["configuration change"]

event_categories("db-security-group") := ["failure", "configuration change"]

valid_event_categories(_, [])

valid_event_categories(_, null)

valid_event_categories(source_type, categories) if {
	every category in event_categories(source_type) {
		category in categories
	}
}

valid_event_subscription(resource) if {
	resource.configuration.enabled != false
	valid_event_categories(resource.configuration.source_type, resource.configuration.event_categories)
}

supported_log_types(engine) := log_types if {
	engine in {"mysql", "mariadb", "aurora", "aurora-mysql"}
	log_types := ["audit", "error", "general", "slowquery"]
}

supported_log_types(engine) := log_types if {
	engine == "postgres"
	log_types := ["postgresql", "upgrade"]
}

supported_log_types(engine) := log_types if {
	engine == "aurora-postgresql"
	log_types := ["postgresql"]
}

supported_log_types(engine) := log_types if {
	engine in {"sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web"}
	log_types := ["agent", "error"]
}

supported_log_types(engine) := log_types if {
	engine in {"oracle-ee", "oracle-se2", "oracle-ee-cdb", "oracle-se2-cdb"}
	log_types := ["alert", "audit", "listener", "oemagent", "trace"]
}

includes_all_log_types(resource) if {
	every log_type in supported_log_types(resource.configuration.engine) {
		log_type in resource.configuration.enabled_cloudwatch_logs_exports
	}
	every log_type in resource.configuration.enabled_cloudwatch_logs_exports {
		log_type in supported_log_types(resource.configuration.engine)
	}
}

valid_log_configuration(resource) if {
	resource.configuration.enabled_cloudwatch_logs_exports
	includes_all_log_types(resource)
}

default_port(engine) := 3306 if engine in {"mysql", "mariadb"}

default_port("postgres") := 5432

default_port(engine) := 1433 if engine in {"sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web"}

default_port(engine) := 1521 if engine in {"oracle-ee", "oracle-se2", "oracle-ee-cdb", "oracle-se2-cdb"}

uses_default_port(instance) if {
	instance.port == default_port(instance.engine)
}

uses_default_port(instance) if not instance.port

parameter_group_requires_tls(family, parameters) if {
	family in {"mysql", "aurora-mysql", "mariadb"}
	some parameter in parameters
	parameter.name == "require_secure_transport"
	parameter.value in [
		true,
		1, "1",
		"true", "True", "TRUE",
		"on", "On", "ON",
	]
}

parameter_group_requires_tls(family, parameters) if {
	family in {"postgres", "aurora-postgresql", "sqlserver"}
	some parameter in parameters
	parameter.name == "rds.force_ssl"
	parameter.value in [
		true,
		1, "1",
		"true", "True", "TRUE",
		"on", "On", "ON",
	]
}

invalid_kms_configuration(instance) if {
	instance.kms_key_id == ""
}

invalid_kms_configuration(instance) if {
	is_null(instance.kms_key_id)
}

invalid_kms_configuration(instance) if not instance.kms_key_id
