"""contrib/github-issue-report against a fake `gh` that records its calls. Needs bash and jq."""

import json
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from tests.support import ROOT, env_with_path, executable

SCRIPT = ROOT / "contrib" / "github-issue-report"
FAKE_GH = """#!/bin/sh
printf '%s' "$*" | tr '\\n' ' ' >> "$LOG"
echo >> "$LOG"
case "$1 $2" in
  "issue list") cat "$STATE/list.json" ;;
  "issue view") cat "$STATE/body.txt" ;;
esac
"""


def counts(blocked: int = 0, pending: int = 0, available: int = 0, active: int = 0) -> dict[str, int]:
    return {"blocked": blocked, "installed_pending_activation": pending, "available": available, "active": active}


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "needs bash and jq")
class GithubIssueReport(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "bin").mkdir()
        executable(self.dir / "bin" / "gh", FAKE_GH)
        executable(self.dir / "bin" / "notify", '#!/bin/sh\nprintf "%s|" "$@" >> "$NOTIFIED"\necho >> "$NOTIFIED"\n')
        self.log = self.dir / "gh.log"
        self.notified = self.dir / "notified"
        self.state(issues=[], body="")
        (self.dir / "report.md").write_text("Security readback: web1\n", encoding="utf-8")

    def state(self, issues: list[dict[str, object]], body: str) -> None:
        (self.dir / "list.json").write_text(json.dumps(issues), encoding="utf-8")
        (self.dir / "body.txt").write_text(body, encoding="utf-8")

    def run_report(self, report: Mapping[str, object], *opts: str) -> subprocess.CompletedProcess[str]:
        (self.dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
        env = env_with_path(self.dir / "bin")
        env.update({"LOG": str(self.log), "STATE": str(self.dir), "NOTIFIED": str(self.notified)})
        cmd = ["bash", str(SCRIPT), "--notify", str(self.dir / "bin" / "notify"), *opts, "web1",
               str(self.dir / "report.md"), str(self.dir / "report.json"), "https://ci.example.org/run/1"]  # fmt: skip
        return subprocess.run(cmd, capture_output=True, text=True, env=env, check=False, timeout=60)

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def notes(self) -> list[str]:
        return self.notified.read_text(encoding="utf-8").splitlines() if self.notified.exists() else []

    def test_opens_an_issue_and_notifies(self) -> None:
        r = self.run_report({"signature": "abc123", "counts": counts(available=2)}, "--repo", "acme/ops")
        self.assertEqual(r.returncode, 0, r.stderr)
        create = [c for c in self.calls() if c.startswith("issue create")]
        self.assertEqual(len(create), 1)
        self.assertIn("--repo acme/ops", create[0])
        self.assertIn("--title Security readback: web1", create[0])
        self.assertIn("<!-- sig:abc123 -->", create[0])
        self.assertEqual(len(self.notes()), 1)
        self.assertIn("|default|shield|web1: blocked 0, pending activation 0, available 2, active 0.", self.notes()[0])

    def test_the_same_picture_updates_quietly(self) -> None:
        self.state([{"number": 7, "title": "Security readback: web1"}], "old\n<!-- sig:abc123 -->\n")
        r = self.run_report({"signature": "abc123", "counts": counts(blocked=1)})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any(c.startswith("issue edit 7") for c in self.calls()))
        self.assertEqual(self.notes(), [])

    def test_another_hosts_issue_is_not_touched(self) -> None:
        self.state([{"number": 8, "title": "Security readback: web10"}], "")
        self.run_report({"signature": "s", "counts": counts(blocked=1)})
        self.assertFalse(any(c.startswith("issue edit 8") for c in self.calls()))
        self.assertTrue(any(c.startswith("issue create") for c in self.calls()))

    def test_clean_closes(self) -> None:
        self.state([{"number": 7, "title": "Security readback: web1"}], "<!-- sig:abc123 -->")
        r = self.run_report({"signature": "e3b0c44298fc", "counts": counts(active=5)})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any(c.startswith("issue comment 7") for c in self.calls()))
        self.assertTrue(any(c.startswith("issue close 7") for c in self.calls()))

    def test_a_failure_streak_notifies_once(self) -> None:
        failed = {"error": "ReadbackError: x", "signature": "failed"}
        self.run_report(failed)
        self.assertEqual(len(self.notes()), 1)
        self.assertIn("|high|warning|", self.notes()[0])
        self.state([{"number": 9, "title": "Security readback: web1"}], "x\n<!-- sig:failed -->\n")
        self.run_report(failed)
        self.assertEqual(len(self.notes()), 1)
        self.assertFalse(any(c.startswith("issue close") for c in self.calls()))

    def test_usage(self) -> None:
        r = subprocess.run(["bash", str(SCRIPT), "only-one"], capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
