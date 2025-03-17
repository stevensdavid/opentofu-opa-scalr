#!/bin/bash
find opentofu-opa -name "*.rego" ! -name "*_test.rego" | while read file; do
    dirpath=$(dirname "$file" | sed 's/^\.\///' | tr '/' '_')
    filename=$(basename "$file")
    cp "$file" "functions/${dirpath}_${filename}"
done
