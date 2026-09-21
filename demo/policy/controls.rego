package finance.release

import rego.v1

deny contains "missing change ticket" if { not input.change.ticket }
deny contains "missing pull request" if { not input.change.pull_request }
deny contains "missing artifact digest" if { not input.artifact.digest }
deny contains "missing artifact digest" if { input.artifact.digest == "" }
deny contains "missing environment validation" if { not input.environment.validated }
deny contains "missing independent approval" if { not input.approval.approved }
deny contains "requester cannot approve their own change" if { input.approval.approver == input.change.requester }
deny contains "production change requires risk approval" if {
  input.environment.name == "production"
  not input.approval.risk_approved
}
deny contains "critical API requires passing contract tests" if {
  input.change.service == "payments-api"
  not input.tests.contract_passed
}
deny contains "fraud release requires passing regression tests" if {
  input.change.service == "fraud-platform"
  not input.tests.fraud_regression_passed
}
deny contains "infrastructure change requires an approved plan" if {
  input.change.service == "infrastructure"
  not input.tests.infrastructure_plan_approved
}

allow if count(deny) == 0
