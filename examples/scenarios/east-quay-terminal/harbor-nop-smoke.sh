#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SCENARIO_DIR="$ROOT/examples/scenarios/east-quay-terminal"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/east-quay-harbor-nop-${USER:-user}.XXXXXX")"
TASK_DIR="$RUN_DIR/task"
JOB_DIR="$RUN_DIR/jobs"
JOB_CONFIG="$RUN_DIR/job.yaml"
JOB_NAME="east-quay-nop-smoke"

uv run python -m src.scenario.render_harbor_task \
  --draft-preview \
  --scenario "$SCENARIO_DIR/scenario.yaml" \
  --range-plan "$SCENARIO_DIR/range-plan.yaml" \
  --catalog "$SCENARIO_DIR/service-catalog.yaml" \
  --catalog-root "$SCENARIO_DIR" \
  --task-assets "$SCENARIO_DIR/harbor-assets" \
  --output "$TASK_DIR"

harbor lint "$TASK_DIR"

cat >"$JOB_CONFIG" <<EOF
job_name: $JOB_NAME
jobs_dir: $JOB_DIR
n_concurrent_trials: 1
agents:
  - name: nop
tasks:
  - path: $TASK_DIR
environment:
  type: docker
  force_build: true
  delete: true
EOF

# Run the task directory directly. This makes Harbor build the generated
# environment/Dockerfile instead of substituting the CLI's default image.
harbor run --config "$JOB_CONFIG"

python3 - "$JOB_DIR/$JOB_NAME" <<'PY'
import json
import sys
from pathlib import Path

job_dir = Path(sys.argv[1])
job_result_path = job_dir / "result.json"
if not job_result_path.is_file():
    raise SystemExit(f"Harbor job result not found: {job_result_path}")
job_result = json.loads(job_result_path.read_text())
if job_result["stats"]["n_completed_trials"] != 1:
    raise SystemExit("expected exactly one completed no-op trial")
if job_result["stats"]["n_errored_trials"] != 0:
    raise SystemExit("no-op trial errored")

trial_results = list(job_dir.glob("*/result.json"))
trial_results = [path for path in trial_results if path.parent != job_dir]
if len(trial_results) != 1:
    raise SystemExit(f"expected one trial result, found {len(trial_results)}")
trial_dir = trial_results[0].parent
trial_result = json.loads(trial_results[0].read_text())
if trial_result["verifier_result"]["rewards"]["reward"] != 0.0:
    raise SystemExit("no-op trial must receive reward 0.0")
if trial_result.get("exception_info") is not None:
    raise SystemExit("no-op trial has exception_info")

artifacts_dir = trial_dir / "artifacts"
manifest_path = artifacts_dir / "manifest.json"
if not manifest_path.is_file():
    raise SystemExit("Harbor artifact manifest is missing")
manifest = json.loads(manifest_path.read_text())
if not manifest or any(item.get("status") != "ok" for item in manifest):
    raise SystemExit(f"Harbor artifact collection was incomplete: {manifest}")

state_path = artifacts_dir / "verifier-state.json"
events_path = artifacts_dir / "yard-broker-observed-commands.jsonl"
if not state_path.is_file() or not events_path.is_file():
    raise SystemExit("verifier sidecar evidence is missing")
state = json.loads(state_path.read_text())
if (
    state.get("clearance_status") != "On Hold"
    or state.get("controller_event_count") != 0
    or state.get("latest_clearance_at_execution") is not None
):
    raise SystemExit(f"unexpected no-op verifier state: {state}")
if events_path.read_text().strip():
    raise SystemExit("no-op run unexpectedly recorded a yard command")

print(
    "Harbor no-op smoke PASS: generated Dockerfile built, sidecar artifacts "
    "collected, resource remained on hold, reward=0.0."
)
print(f"Task, job, and evidence retained under {job_dir.parent}")
PY
