package aws.controls.ecs

import rego.v1

# Root user UID can be integer 0 or a string
is_root_user(container) if container.user == 0

is_root_user(container) if regex.match(`0|root|^0:.*$|^root:.*$`, container.user)

# ECS defaults to root user if unspecified
is_root_user(container) if {
	not container.user
}

task_doesnt_use_awsvpc(resource) if {
	resource.configuration.network_mode != "awsvpc"
}

task_doesnt_use_awsvpc(resource) if {
	not resource.configuration.network_mode
}

cluster_insights_is_disabled(cluster) if {
	some setting in cluster.setting
	setting.name == "containerInsights"
	setting.value != "enabled"
}

cluster_insights_is_disabled(cluster) if {
	every setting in cluster.setting {
		setting.name != "containerInsights"
	}
}

cluster_insights_is_disabled(cluster) if {
	not cluster.setting
}
