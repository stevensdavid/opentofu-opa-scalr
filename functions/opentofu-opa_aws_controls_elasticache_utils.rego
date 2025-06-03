package aws.controls.elasticache

engine_version_is_greater_or_equal(engine_version, major_version) if to_number(split(engine_version, ".")[0]) >= major_version

engine_version_is_greater_or_equal(engine_version, null)
