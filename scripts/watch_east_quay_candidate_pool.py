#!/usr/bin/env python3
"""Poll pentest_design/main and report candidate-pool changes for review.

This watcher is intentionally read-only with respect to both repositories:
candidate rows are surfaced for human review and are never copied into a
range plan automatically.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PART_RE = re.compile(r"\[(candidates/part-\d+\.md)\]")
SNAPSHOT_RE = re.compile(
    r"(\d+) candidate rows.*?\nSnapshot ([0-9-]+).*?batch-(\d+) header",
    re.DOTALL,
)
ROW_RE = re.compile(r"^\+\|\s*(\d+)\s*\|\s*([^|]+)\|")
EAST_QUAY_RE = re.compile(r"East Quay", re.IGNORECASE)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def fetch_main(repo: Path) -> str:
    subprocess.run(
        ["git", "-C", str(repo), "fetch", "origin", "main", "--quiet"],
        check=True,
        capture_output=True,
        text=True,
    )
    return git(repo, "rev-parse", "origin/main").strip()


def snapshot_summary(repo: Path, commit: str) -> tuple[str, list[str]]:
    index = git(repo, "show", f"{commit}:CANDIDATES.md")
    match = SNAPSHOT_RE.search(index)
    if match:
        summary = (
            f"{match.group(1)} rows, snapshot {match.group(2)}, "
            f"through batch {match.group(3)}"
        )
    else:
        summary = "snapshot metadata not parsed"
    parts = sorted(set(PART_RE.findall(index)))
    return summary, parts


def report_delta(repo: Path, previous: str, current: str) -> None:
    summary, _ = snapshot_summary(repo, current)
    print(
        f"[{datetime.now(timezone.utc).isoformat()}] "
        f"candidate pool changed: {previous[:12]} -> {current[:12]} ({summary})",
        flush=True,
    )
    changed = git(
        repo,
        "diff",
        "--name-only",
        previous,
        current,
        "--",
        "CANDIDATES.md",
        "candidates/",
    ).splitlines()
    for path in changed:
        if not re.fullmatch(r"candidates/part-\d+\.md", path):
            continue
        diff = git(repo, "diff", "--unified=0", previous, current, "--", path)
        found_row = False
        for line in diff.splitlines():
            row = ROW_RE.match(line)
            if row:
                found_row = True
                print(
                    f"  candidate row #{row.group(1)}: {row.group(2).strip()} "
                    f"({path})",
                    flush=True,
                )
            elif line.startswith("+") and not line.startswith("+++") and EAST_QUAY_RE.search(line):
                print(f"  East Quay note ({path}): {line[1:].strip()}", flush=True)
        if not found_row:
            print(f"  changed candidate content: {path}", flush=True)
    print(
        "  Review the source row and its evidence before editing MHBench; "
        "no candidate is auto-selected.",
        flush=True,
    )


def load_state(path: Path) -> str | None:
    try:
        state = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    return state.get("last_seen_main")


def save_state(path: Path, commit: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(
            {
                "last_seen_main": commit,
                "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        )
        + "\n"
    )
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        required=True,
        help="Local pentest_design clone with origin/main configured.",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path.home() / ".cache/mhbench/east-quay-candidate-watch.json",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=300,
        help="Polling interval for --watch (default: 300 seconds).",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Keep polling until interrupted; default is a single check.",
    )
    args = parser.parse_args()
    repo = args.repo.expanduser().resolve()
    if not (repo / ".git").exists():
        parser.error(f"--repo is not a Git clone: {repo}")
    if args.interval_seconds < 30:
        parser.error("--interval-seconds must be at least 30")

    previous = load_state(args.state_file)
    while True:
        try:
            current = fetch_main(repo)
            summary, _ = snapshot_summary(repo, current)
            if previous is None:
                print(
                    f"Monitoring initialized at {current[:12]} ({summary}); "
                    "no initial candidate selection is made.",
                    flush=True,
                )
            elif current != previous:
                report_delta(repo, previous, current)
            else:
                print(
                    f"[{datetime.now(timezone.utc).isoformat()}] "
                    f"no change at {current[:12]} ({summary})",
                    flush=True,
                )
            save_state(args.state_file, current)
            previous = current
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"candidate-pool check failed (will retry): {error}", file=sys.stderr, flush=True)
        if not args.watch:
            return 0
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
