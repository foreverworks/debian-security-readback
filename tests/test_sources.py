import io
import unittest

from debian_security_readback.debversion import compare_versions, is_version
from debian_security_readback.model import ReadbackError
from debian_security_readback.sources import (
    fix_urgency,
    iter_tracker,
    load_urgencies,
    parse_dsa_list,
    validate_dsa_text,
)
from tests.support import DSA, filler_dsa, tracker_text


class Versions(unittest.TestCase):
    def test_order(self) -> None:
        c = compare_versions
        self.assertEqual(c("1.0-1", "1.0-1"), 0)
        self.assertEqual(c("1.0~rc1-1", "1.0-1"), -1)
        self.assertEqual(c("1:0.9-1", "2.0-1"), 1)
        self.assertEqual(c("1.24.2-3+deb13u1", "1.24.2-3"), 1)
        self.assertEqual(c("3.0.20-1~deb12u2", "3.0.9-1"), 1)
        self.assertEqual(c("6.12.9-1", "6.12.10-1"), -1)
        self.assertEqual(c("1.0", "1.0-0"), 0)
        self.assertEqual(c("1.0a-1", "1.0-1"), 1)
        self.assertEqual(c("1.0+b1", "1.0~"), 1)

    def test_markers_are_not_versions(self) -> None:
        self.assertTrue(is_version("1:2.3-4+deb13u1"))
        self.assertFalse(is_version("<end-of-life>"))
        self.assertFalse(is_version("<not-affected>"))


class DsaList(unittest.TestCase):
    def test_keeps_the_release_asked_for_and_skips_markers(self) -> None:
        fixes = parse_dsa_list(DSA, "trixie")
        self.assertEqual(
            [(f["source"], f["fixed_version"], f["date"]) for f in fixes],
            [("gpgme1.0", "1.24.2-3+deb13u1", "2026-11-20"), ("linux", "6.12.70-1", "2026-11-19")],
        )
        self.assertEqual(fixes[0]["cves"], ["CVE-2026-1", "CVE-2026-2"])
        self.assertEqual([f["source"] for f in parse_dsa_list(DSA, "bookworm")], ["gpgme1.0", "oldthing"])

    def test_garbage_fails_instead_of_reading_clean(self) -> None:
        for text in ("", "<html><title>Making sure you are not a bot</title></html>", DSA):
            with self.assertRaises(ReadbackError):
                validate_dsa_text(text, "trixie")
        self.assertEqual(len(validate_dsa_text(DSA + filler_dsa(), "trixie")), 122)

    def test_a_release_without_dsas_fails(self) -> None:
        with self.assertRaises(ReadbackError):
            validate_dsa_text(DSA + filler_dsa(), "forky")


class Tracker(unittest.TestCase):
    def test_streams_in_small_chunks_and_keeps_wanted_only(self) -> None:
        out = load_urgencies(io.StringIO(tracker_text()), {"pkg7", "pkg1499"}, "trixie")
        self.assertEqual(out, {"pkg7": {"CVE-7": "high"}, "pkg1499": {"CVE-1499": "high"}})
        got = list(iter_tracker(io.StringIO(tracker_text(3)), chunk=17))
        self.assertEqual([k for k, _ in got], ["pkg0", "pkg1", "pkg2"])

    def test_another_release_has_no_urgency(self) -> None:
        out = load_urgencies(io.StringIO(tracker_text()), {"pkg7"}, "bookworm")
        self.assertEqual(out, {"pkg7": {"CVE-7": None}})

    def test_wrong_shape_fails(self) -> None:
        for text in ("<html>challenge</html>", "{}", '{"a": {"CVE-1": {}}}', "[1,2]", '{"a": 1}', tracker_text()[:-30], ""):
            with self.assertRaises(ReadbackError, msg=text[:40]):
                load_urgencies(io.StringIO(text), set(), "trixie")

    def test_urgency_is_the_highest_of_the_cves(self) -> None:
        t: dict[str, dict[str, str | None]] = {"p": {"CVE-1": "low", "CVE-2": "high", "CVE-3": None}}
        self.assertEqual(fix_urgency(t, "p", ["CVE-1", "CVE-2"]), "high")
        self.assertEqual(fix_urgency(t, "p", ["CVE-3"]), "unknown")
        self.assertEqual(fix_urgency(t, "q", ["CVE-1"]), "unknown")


if __name__ == "__main__":
    unittest.main()
