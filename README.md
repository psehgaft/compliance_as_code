# Compliance as Code for Finance

Demo for the DevConf US 2026 talk: a banking release moves through a versioned policy decision, a recorded approval, a simulated deployment, drift detection, and controlled local recovery. It uses synthetic data only.

## What the demo proves

| Control | Executable example | Evidence |
| --- | --- | --- |
| Policy as code | OPA/Rego checks required change, approval, test, and environment fields | `policy_decision` event and policy SHA-256 |
| Change traceability | Ticket, pull request, artifact digest, requester and approver are inputs | Input SHA-256 and approval record in the event |
| Evidence collection | Each event includes a hash of its canonical contents and the previous hash | `demo/output/evidence.jsonl`; `verify` detects tampering |
| Drift and recovery | Compare deployed local JSON against desired JSON and require `--recover` before restoring | `drift_detected` and `recovery_simulated` events |
| Banking use cases | Payments API, fraud platform, infrastructure scenarios | Three synthetic JSON requests |

This is a **local simulation**. The approval field is sample input, not an authenticated approval. The hash chain is tamper evident only if its final hash is anchored in trusted storage; the demo does not provide immutable storage, cryptographic signatures, SBOMs, vulnerability scans, OSCAL export, Argo CD, or real cluster rollback. Production integration needs identity backed approvals, signed artifacts, protected audit storage, CI/CD gates, and an operations runbook.

## Prerequisites

- Python 3.9+
- OPA CLI 1.x on `PATH` (the workflow pins OPA 1.8.0)

## Run the 8 minute demo

From the repository root:

```bash
opa test demo/policy -v
python3 -m unittest discover -s demo/tests -v
python3 demo/run.py run demo/scenarios/approved-payment.json
python3 demo/run.py run demo/scenarios/rejected-fraud.json  # expected exit code: 2
python3 demo/run.py run demo/scenarios/approved-infrastructure.json --inject-drift
python3 demo/run.py run demo/scenarios/approved-infrastructure.json --inject-drift --recover
python3 demo/run.py verify demo/output/evidence.jsonl
```

The third run intentionally exits with code 3 and leaves drift for operator review; the fourth run simulates authorized recovery. Each command appends evidence in the chosen output directory. For a clean run use `--output /tmp/compliance-demo-1` on each command or remove `demo/output/` first. Inspect `demo/output/evidence.jsonl` and `demo/output/deployed.json` to discuss the linked change, policy decision and observed state.

To show tamper detection, copy `evidence.jsonl`, change a field in its first line, then run `verify` on the altered copy. It exits 1 with the broken record number. Never edit the production log for a demo.

### Expected decisions

| Scenario | Result | Why |
| --- | --- | --- |
| `approved-payment.json` | Approved | Independent approval, risk approval, validated environment and passing contract test |
| `rejected-fraud.json` | Blocked | Self approval, missing risk approval and failing fraud regression |
| `approved-infrastructure.json` | Approved; drift can be injected | Approved plan; local recovery requires an explicit option |

## How to adapt it

Replace fixture fields with verified data from your change system, CI test results, artifact registry and identity provider. Gate deployment on OPA's `allow` result. Export the decision with commit SHA, image digest, test report references, approver identity and policy version to protected storage. Integrate reconciliation with Argo CD or another controller, with explicit controls for when to alert versus remediate. The simulation keeps these boundaries visible so an operator can explain every release and recovery event.

## Slides

The accompanying DevConf presentation is titled **Compliance as Code for Finance**. The live sequence illustrates policy as code, environment validation, evidence, traceability, drift and recovery across the abstract's banking cases.
