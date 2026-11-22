import unittest

from debian_security_readback.decide import classify
from debian_security_readback.model import Kernel, StaleDocker
from debian_security_readback.report import build, failed, render, render_failed
from debian_security_readback.sources import parse_dsa_list
from tests.support import DSA, NOKERNEL, TODAY, pkg


class Render(unittest.TestCase):
    def test_counts_open_rows_and_containers(self) -> None:
        rows = classify(parse_dsa_list(DSA, "trixie"), [pkg("gpgme1.0", "1.0-1")], {}, set(), {}, NOKERNEL, {}, TODAY)
        stale: list[StaleDocker] = [
            {"name": "web", "image": "nginx:1", "image_id": "sha256:" + "a" * 64, "current_id": "sha256:" + "b" * 64}
        ]
        md = render("web1.example.org", rows, NOKERNEL, stale, None, TODAY, ["a note"])
        self.assertIn("Security readback: web1.example.org, 2026-11-21", md)
        self.assertIn("| blocked | 1 |", md)
        self.assertNotIn("| active | 1 |", md)
        self.assertIn("DSA-6646-1", md)
        self.assertIn("**Warning:** a note", md)
        self.assertIn("- web runs nginx:1 sha256:aaaaaaaaaaaa, the tag is now sha256:bbbbbbbbbbbb", md)
        self.assertIn("### Incus containers behind their image\nNot present or not readable on this host.", md)

    def test_all_active(self) -> None:
        k: Kernel = {"installed": "6.12.70-1", "running": "6.12.70-1", "release": "6.12.70-amd64"}
        installed = [pkg("gpgme1.0", "1.24.2-3+deb13u1"), pkg("linux-image-6.12.70-amd64", "6.12.70-1", "linux-signed-amd64")]
        rows = classify(parse_dsa_list(DSA, "trixie"), installed, {}, set(), {}, k, {}, TODAY)
        self.assertEqual([r["state"] for r in rows], ["active", "active"])
        md = render("h", rows, k, [], [], TODAY, recent_days=1)
        self.assertNotIn("### Not active", md)
        self.assertIn("Active in the last 1 days: 1 of 2", md)
        self.assertIn("None: every running one", md)
        report = build("h", "trixie", rows, k, [], [], TODAY, [], 10)
        self.assertEqual((report["schema"], report["counts"]["active"], report["kernel"]["running"]), (1, 2, "6.12.70-1"))

    def test_failure_never_reads_clean(self) -> None:
        f = failed("h", TODAY, "ReadbackError: no data")
        self.assertEqual((f["signature"], f["error"]), ("failed", "ReadbackError: no data"))
        self.assertIn("failed on h", render_failed("h", "x"))


if __name__ == "__main__":
    unittest.main()
