#!/usr/bin/env python3
"""Local, simulated banking release demo. Requires the OPA CLI for policy evaluation."""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
POLICY = ROOT / "policy" / "controls.rego"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def append(log, event):
    previous = "0" * 64
    if log.exists() and log.stat().st_size:
        previous = json.loads(log.read_text().splitlines()[-1])["hash"]
    record = {"time": datetime.now(timezone.utc).isoformat(), "previous": previous, **event}
    record["hash"] = digest(record)
    with log.open("a", encoding="utf-8") as out:
        out.write(canonical(record) + "\n")
    return record


def verify(log):
    previous = "0" * 64
    for number, line in enumerate(log.read_text().splitlines(), 1):
        record = json.loads(line)
        actual = record.pop("hash")
        if record["previous"] != previous or digest(record) != actual:
            raise ValueError(f"evidence chain broken at record {number}")
        previous = actual
    return number if 'number' in locals() else 0


def evaluate(opa, scenario):
    cmd = [opa, "eval", "--format", "raw", "--data", str(POLICY), "--input", str(scenario), "data.finance.release.deny"]
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"OPA evaluation failed: {exc}; install OPA 1.x and run opa test demo/policy") from exc
    return json.loads(result.stdout)


def run(args):
    scenario = Path(args.scenario).resolve()
    release = json.loads(scenario.read_text())
    reasons = evaluate(args.opa, scenario)
    work = Path(args.output).resolve()
    work.mkdir(parents=True, exist_ok=True)
    log, state = work / "evidence.jsonl", work / "deployed.json"
    release_id = release["change"]["ticket"]
    append(log, {"event": "policy_decision", "change": release_id, "input_sha256": digest(release),
                 "policy_sha256": hashlib.sha256(POLICY.read_bytes()).hexdigest(),
                 "allowed": not reasons, "reasons": reasons,
                 "approval_record": release["approval"], "artifact_digest": release["artifact"]["digest"]})
    if reasons:
        print(f"BLOCKED {release_id}: {', '.join(sorted(reasons))}")
        return 2
    desired = {"service": release["change"]["service"], "artifact_digest": release["artifact"]["digest"], "change": release_id}
    state.write_text(canonical(desired) + "\n")
    append(log, {"event": "deployment_simulated", "change": release_id, "desired_sha256": digest(desired)})
    if args.inject_drift:
        drifted = {**desired, "artifact_digest": "sha256:UNAPPROVED"}
        state.write_text(canonical(drifted) + "\n")
        append(log, {"event": "drift_injected_for_demo", "change": release_id})
    observed = json.loads(state.read_text())
    if observed != desired:
        append(log, {"event": "drift_detected", "change": release_id, "observed_sha256": digest(observed), "desired_sha256": digest(desired)})
        if args.recover:
            state.write_text(canonical(desired) + "\n")
            append(log, {"event": "recovery_simulated", "change": release_id, "authorization": "--recover", "desired_sha256": digest(desired)})
            print(f"DRIFT DETECTED AND RECOVERED {release_id}")
        else:
            print(f"DRIFT DETECTED {release_id}; operator review required")
            return 3
    else:
        print(f"APPROVED {release_id}; simulated deployment matches desired state")
    print(f"Evidence: {log}; records: {verify(log)}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    execute = sub.add_parser("run")
    execute.add_argument("scenario", help="JSON release request")
    execute.add_argument("--opa", default="opa", help="OPA CLI path")
    execute.add_argument("--output", default="demo/output", help="local simulation directory")
    execute.add_argument("--inject-drift", action="store_true")
    execute.add_argument("--recover", action="store_true", help="authorize local recovery simulation")
    check = sub.add_parser("verify")
    check.add_argument("evidence", help="JSONL evidence file")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            print(f"Evidence chain valid: {verify(Path(args.evidence))} records")
            return 0
        if args.recover and not args.inject_drift:
            parser.error("--recover requires --inject-drift")
        return run(args)
    except (ValueError, RuntimeError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
