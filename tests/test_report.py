import unittest

from debian_security_readback.decide import classify
from debian_security_readback.model import Kernel, StaleDocker
from debian_security_readback.report import build, cell, failed, render, render_failed
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
        self.assertIn("### Incus containers behind their image\nNot present, turned off, or not readable on this host.", md)

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

    def test_what_a_process_calls_itself_cannot_break_out(self) -> None:
        rows = classify(parse_dsa_list(DSA, "trixie"), [pkg("gpgme1.0", "1.24.2-3+deb13u1")], {}, set(),
                        {"gpgme1.0": ["a|b`c@admin<img src=x>[l](u)\\(1)"]}, NOKERNEL, {}, TODAY)  # fmt: skip
        md = render("h", rows, NOKERNEL, None, None, TODAY, ["note\n| injected | row |"])
        line = next(x for x in md.splitlines() if x.startswith("| installed_pending_activation | DSA-6646-1"))
        self.assertIn("a\\|b\\`c&#64;admin&lt;img src=x&gt;\\[l\\](u)\\\\(1)", line)
        self.assertEqual(line.count(" | "), 6)
        self.assertNotIn("\n| injected", md)
        self.assertEqual(cell("#12 https://x.example"), "&#35;12 https:&#47;&#47;x.example")
        failed_md = render_failed("h", "boom @admin <b>\nsecond line")
        self.assertIn("\n    boom @admin <b>\n    second line\n", failed_md)

    def test_failure_never_reads_clean(self) -> None:
        f = failed("h", TODAY, "ReadbackError: no data")
        self.assertEqual((f["signature"], f["error"]), ("failed", "ReadbackError: no data"))
        self.assertIn("failed on h", render_failed("h", "x"))


if __name__ == "__main__":
    unittest.main()
