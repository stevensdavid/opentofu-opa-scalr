# Scalr Open Policy Agent policies

This repository contains an example of how the [`stevensdavid/opentofu-opa`](https://github.com/stevensdavid/opentofu-opa) repository can be used with Scalr as your OpenTofu backend.

## Configuring Scalr

In order to start using the examples, create a Open Policy Agent policy group under the integrations tab in Scalr.
Point Scalr to your fork of this repository, set policies folder to `terraform` and the common functions folder to `functions`.
Ensure that OPA version is set to at least 1.0.0.

Start enforcing the policy group in some environments, and see your plans be evaluated.

The specific policy enforcement configuration is done in [`terraform/scalr-policy.hcl`](terraform/scalr-policy.hcl).
In this example, we run the AWS controls.
If any controls are violated, Scalr will issue a warning.
If high severity controls are violated, Scalr will require approval from a user with the `policy-checks:override` permission to apply the changes.

## Updating `opentofu-opa`

As Scalr does not yet support OPA bundles, we need to flatten the `opentofu-opa` package so it can be imported using the common functions feature in Scalr.

This repository uses a [Git hook](.githooks/pre-commit) to automatically perform this bundling upon updates to `opentofu-opa`, so make sure that you run `git config core.hooksPath .githooks` after cloning the repository the first time.
The result of this is that the git will automatically run the bundling script and add the result to your commit when you pull changes to the submodule `opentofu-opa`.
