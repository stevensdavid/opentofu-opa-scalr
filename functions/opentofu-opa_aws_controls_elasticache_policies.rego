package aws.controls.elasticache

import data.aws.utils as aws_utils
import data.utils

evaluate_elasticache_1(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_elasticache_cluster")

	configuration.engine in {"valkey", "redis"}
	utils.falsy(configuration.snapshot_retention_limit)

	violation := {
		"id": {"opa": "aws.controls.elasticache.1"},
		"reason": "Require an Amazon ElastiCache (Redis OSS) cluster to have automatic backups activated",
		"resource": address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolselasticache1",
	}
}

evaluate_elasticache_2(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_elasticache_cluster")

	configuration.engine in {"valkey", "redis"}
	configuration.auto_minor_version_upgrade == "false"
	engine_version_is_greater_or_equal(configuration.engine_version, 6)

	violation := {
		"id": {"opa": "aws.controls.elasticache.2"},
		"reason": "Require an Amazon ElastiCache (Redis OSS) cluster to have automatic minor version upgrades activated",
		"resource": address,
		"severity": "high",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolselasticache2",
	}
}
