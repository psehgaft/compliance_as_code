package finance.release

import rego.v1

base := {
  "change": {"ticket": "CHG-1042", "pull_request": "PR-42", "requester": "engineer", "service": "payments-api"},
  "artifact": {"digest": "sha256:example"},
  "environment": {"name": "production", "validated": true},
  "approval": {"approved": true, "approver": "risk-reviewer", "risk_approved": true},
  "tests": {"contract_passed": true}
}

test_approved_payment if { allow with input as base }
test_reject_missing_contract if {
  not allow with input as object.union(base, {"tests": {"contract_passed": false}})
}
test_reject_self_approval if {
  not allow with input as object.union(base, {"approval": {"approved": true, "approver": "engineer", "risk_approved": true}})
}
test_reject_missing_risk_approval if {
  not allow with input as object.union(base, {"approval": {"approved": true, "approver": "risk-reviewer", "risk_approved": false}})
}
test_reject_missing_digest if {
  not allow with input as object.union(base, {"artifact": {"digest": ""}})
}
