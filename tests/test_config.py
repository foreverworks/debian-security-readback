import tempfile
import unittest
from pathlib import Path

from debian_security_readback.cli import detect_release
from debian_security_readback.config import Config, ConfigError, from_mapping, load, parse
from debian_security_readback.model import ReadbackError

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "config.toml"


class ConfigFile(unittest.TestCase):
    def test_defaults(self) -> None:
        c = Config()
        self.assertEqual((c.host, c.release, c.recent_days, c.docker, c.fail_on), ("", "", 30, True, ()))
        self.assertIn("security-tracker.debian.org", c.tracker_url)

    def test_file_then_flags(self) -> None:
        c = parse('release = "trixie"\nrecent_days = 7\nfail_on = ["blocked"]\ndocker = false\n')
        self.assertEqual((c.release, c.recent_days, c.fail_on, c.docker, c.incus), ("trixie", 7, ("blocked",), False, True))
        self.assertEqual(parse("report_mode = 0o600\n").report_mode, 0o600)
        self.assertEqual(parse('tracker_url = "file:///srv/mirror/json"\n').tracker_url, "file:///srv/mirror/json")
        c2 = from_mapping({"recent_days": 9}, c)
        self.assertEqual((c2.release, c2.recent_days), ("trixie", 9))

    def test_refuses_what_it_cannot_use(self) -> None:
        for text in (
            "unknown = 1",
            'recent_days = "7"',
            "recent_days = -1",
            "recent_days = true",
            'docker = "no"',
            'fail_on = ["patched"]',
            "container_cgroup_patterns = [1]",
            'container_cgroup_patterns = [""]',
            "container_cgroup_patterns = ['(unclosed']",
            "download_deadline_seconds = 0",
            "command_timeout_seconds = 0",
            "tracker_max_mib = 0",
            "report_mode = 0o1777",
            'cache_dir = "relative/dir"',
            'out_dir = ""',
            'tracker_url = "http://mirror.example.org/json"',
            'dsa_list_url = "ftp://mirror.example.org/list"',
            'dsa_list_url = "https:///no-host"',
            "release = 13",
            "not toml",
        ):
            with self.assertRaises(ConfigError, msg=text):
                parse(text)

    def test_load(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConfigError):
                load(d + "/missing.toml")
            p = Path(d) / "c.toml"
            p.write_text('host = "web1"\n', encoding="utf-8")
            self.assertEqual(load(str(p)).host, "web1")

    def test_the_example_is_the_defaults(self) -> None:
        """examples/config.toml documents every key at its default: commented out it is the defaults,
        uncommented it must parse to them too."""
        lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
        body = "\n".join(line[2:] for line in lines if line.startswith("# "))
        c = parse(body)
        self.assertEqual(c, Config())


class Release(unittest.TestCase):
    def test_debian(self) -> None:
        self.assertEqual(detect_release("ID=debian\nVERSION_CODENAME=trixie\n"), "trixie")

    def test_not_debian_or_no_codename(self) -> None:
        for text in ("ID=ubuntu\nVERSION_CODENAME=noble\n", "ID=debian\n", ""):
            with self.assertRaises(ReadbackError):
                detect_release(text)
        with self.assertRaisesRegex(ReadbackError, "Debian unstable"):
            detect_release('ID=debian\nPRETTY_NAME="Debian GNU/Linux forky/sid"\n')


if __name__ == "__main__":
    unittest.main()
