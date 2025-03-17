#!/bin/bash
set -euo pipefail

output='{"mocks": {}}'

for file in "$@"; do
    # Only check JSON files:
    if [[ ! "$file" =~ \.json$ ]]; then
        continue
    fi
    echo "Processing $file..." >&2
    if ! jq '.' "$file" >/dev/null 2>&1; then
        echo "Error: Invalid JSON in $file" >&2
        exit 1
    fi

    # Split the path into components and build the JSON structure
    IFS='/' read -r -a path_parts <<<"$file"
    content=$(cat "$file")

    # Build nested structure using jq, maintaining the full path structure
    # Since this is being run from one directory up, the path parts are going to be
    # 0: test_data (static string that we discard)
    # 1: SERVICE
    # 2: CONTROL_NUMBER
    path_length=${#path_parts[@]}
    service="${path_parts[path_length - 3]}"
    num="${path_parts[path_length - 2]}"
    output=$(echo "$output" | jq --arg content "$content" \
        --arg service "$service" \
        --arg num "$num" '
        .mocks[$service][$num] = ($content | fromjson)
    ')
done
echo "$output"
