import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from scripts.watch_east_quay_candidate_pool import report_delta


class CandidateWatcherTest(unittest.TestCase):
    def test_delta_output_surfaces_rows_without_dumping_long_history(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            env = os.environ.copy()
            env.update(
                GIT_AUTHOR_NAME="Candidate watcher test",
                GIT_AUTHOR_EMAIL="watcher-test@example.invalid",
                GIT_COMMITTER_NAME="Candidate watcher test",
                GIT_COMMITTER_EMAIL="watcher-test@example.invalid",
            )

            (repo / "candidates").mkdir()
            (repo / "CANDIDATES.md").write_text(
                "1 candidate rows\nSnapshot 2026-11-20 through batch-1 header\n"
                "[candidates/part-01.md](candidates/part-01.md)\n"
            )
            part = repo / "candidates/part-01.md"
            part.write_text("| # | Project |\n|---|---|\n")
            subprocess.run(
                ["git", "-C", str(repo), "add", "."], check=True, env=env
            )
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "base"],
                check=True,
                env=env,
            )
            previous = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            additions = [
                "| 451 | Dolibarr ticket module | 24.0.3 | fix abc123 | "
                "Broken object-level authorization in mass close/reopen actions; "
                "restricted agent can target another user's ticket by POSTing "
                "row IDs |",
                *[
                    f"- East Quay hold-watch batch {index}: " + ("detail " * 100)
                    for index in range(5)
                ],
            ]
            part.write_text(
                "| # | Project |\n|---|---|\n"
                + "\n".join(additions)
                + "\n"
            )
            subprocess.run(
                ["git", "-C", str(repo), "add", "."], check=True, env=env
            )
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "candidate update"],
                check=True,
                env=env,
            )
            current = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            output = StringIO()
            with redirect_stdout(output):
                report_delta(repo, previous, current)

            rendered = output.getvalue()
            self.assertIn("candidate row #451: Dolibarr ticket module", rendered)
            self.assertIn(
                "Broken object-level authorization in mass close/reopen actions",
                rendered,
            )
            self.assertIn(
                "5 distinct added lines; showing latest 3, 2 omitted", rendered
            )
            self.assertLessEqual(
                max(map(len, rendered.splitlines())), 400
            )


if __name__ == "__main__":
    unittest.main()
