"""The whole command, end to end, on a fake host: dpkg, apt and Docker are small scripts on PATH, the
tracker's files are local fixtures served as file:// URLs."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from debian_security_readback.files import exclusive_lock
from tests.support import DSA, ROOT, env_with_path, executable, filler_dsa, tracker_text

INSTALLED = [
    # name, version, source, source version, status
    ("gpgme1.0", "1.0-1", "gpgme1.0", "1.0-1", "ii "),
    ("libheld1", "2.0-1", "held", "2.0-1", "ii "),
    ("libok1", "3.0-2", "okpkg", "3.0-2", "ii "),
    ("gone", "1-1", "gone", "1-1", "rc "),
]
EXTRA_DSA = """[15 Nov 2026] DSA-6400-1 held - security update
\t{CVE-2026-40}
\t[trixie] - held 2.0-2
[14 Nov 2026] DSA-6300-1 okpkg - security update
\t[trixie] - okpkg 3.0-2
"""


class Cli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        dpkg_lines = "".join("%s\\t%s\\t%s\\t%s\\t%s\\n" % row for row in INSTALLED)
        executable(
            self.bin / "dpkg-query",
            "#!/bin/sh\ncase \"$1\" in -W) printf '%s' ;; -S) exit 1 ;; esac\n" % dpkg_lines,
        )
        executable(self.bin / "apt-mark", '#!/bin/sh\n[ "$1" = showhold ] && echo libheld1\n')
        executable(
            self.bin / "apt-cache",
            '#!/bin/sh\nshift\nfor p in "$@"; do\n  echo "$p:"\n'
            '  case "$p" in gpgme1.0) echo "  Candidate: 1.24.2-3+deb13u1" ;; libheld1) echo "  Candidate: 2.0-2" ;;'
            ' *) echo "  Candidate: (none)" ;; esac\ndone\n',
        )
        self.dsa = self.dir / "dsa-list"
        self.dsa.write_text(DSA + EXTRA_DSA + filler_dsa(), encoding="utf-8")
        self.tracker = self.dir / "tracker.json"
        self.tracker.write_text(tracker_text(extra={"held": {"CVE-2026-40": "medium"}}), encoding="utf-8")
        self.out = self.dir / "out"

    def config(self, **extra: str) -> Path:
        values = {
            "host": '"web1.example.org"',
            "release": '"trixie"',
            "cache_dir": '"%s"' % (self.dir / "cache"),
            "out_dir": '"%s"' % self.out,
            "dsa_list_url": '"%s"' % self.dsa.as_uri(),
            "tracker_url": '"%s"' % self.tracker.as_uri(),
            "docker": "false",
            "incus": "false",
            **extra,
        }
        p = self.dir / "config.toml"
        p.write_text("".join("%s = %s\n" % kv for kv in values.items()), encoding="utf-8")
        return p

    def run_cli(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, "-I", str(ROOT / "bin" / "debian-security-readback"), *args]
        full_env = {**env_with_path(self.bin), **env}
        return subprocess.run(cmd, capture_output=True, text=True, env=full_env, check=False, timeout=120)

    def report(self) -> dict[str, object]:
        data: dict[str, object] = json.loads((self.out / "report.json").read_text(encoding="utf-8"))
        return data

    def test_report(self) -> None:
        r = self.run_cli("--config", str(self.config()))
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = self.report()
        fixes = rep["fixes"]
        assert isinstance(fixes, list)
        states = {(f["source"], f["state"]) for f in fixes}
        self.assertEqual(states, {("held", "blocked"), ("gpgme1.0", "available"), ("okpkg", "active")})
        self.assertEqual(rep["counts"], {"blocked": 1, "installed_pending_activation": 0, "available": 1, "active": 1})
        self.assertEqual((rep["host"], rep["release"], rep["docker_stale"]), ("web1.example.org", "trixie", None))
        held = next(f for f in fixes if f["source"] == "held")
        self.assertEqual((held["urgency"], held["reason"]), ("medium", "on hold: libheld1"))
        self.assertTrue(r.stdout.rstrip().splitlines()[-1].startswith("SECURITY_READBACK counts="))
        md = (self.out / "report.md").read_text(encoding="utf-8")
        self.assertIn("| available | 1 |", md)

    def test_flags_override_the_file_and_fail_on(self) -> None:
        r = self.run_cli("--config", str(self.config()), "--host", "db1", "--fail-on", "blocked,available")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertEqual(self.report()["host"], "db1")
        self.assertIn("1 blocked, 1 available", r.stderr)
        r = self.run_cli("--config", str(self.config()), "--fail-on", "installed_pending_activation")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_bad_source_data_fails_and_says_so(self) -> None:
        self.dsa.write_text("<html>challenge</html>", encoding="utf-8")
        (self.out).mkdir()
        (self.out / "report.json").write_text('{"signature": "clean-old"}', encoding="utf-8")
        r = self.run_cli("--config", str(self.config()))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not the DSA list", r.stderr)
        rep = self.report()
        self.assertEqual(rep["signature"], "failed")
        self.assertIn("not the DSA list", str(rep["error"]))
        self.assertIn("failed on web1.example.org", (self.out / "report.md").read_text(encoding="utf-8"))

    def test_a_stale_cache_is_used_with_a_note(self) -> None:
        cfg = self.config(cache_max_age_hours="0")
        self.assertEqual(self.run_cli("--config", str(cfg)).returncode, 0)
        self.dsa.unlink()
        r = self.run_cli("--config", str(cfg))
        self.assertEqual(r.returncode, 0, r.stderr)
        notes = self.report()["notes"]
        assert isinstance(notes, list)
        self.assertTrue(any("could not be refreshed" in n for n in notes), notes)

    def test_a_fresh_cache_is_not_downloaded_again(self) -> None:
        cfg = self.config()
        self.assertEqual(self.run_cli("--config", str(cfg)).returncode, 0)
        self.dsa.unlink()
        r = self.run_cli("--config", str(cfg))
        self.assertEqual(r.returncode, 0, r.stderr)
        notes = self.report()["notes"]
        assert isinstance(notes, list)
        self.assertFalse([n for n in notes if "refreshed" in n])

    def test_configuration_errors_exit_2(self) -> None:
        self.assertEqual(self.run_cli("--config", str(self.config(recent_days='"x"'))).returncode, 2)
        self.assertEqual(self.run_cli("--config", str(self.dir / "nope.toml")).returncode, 2)
        self.assertEqual(self.run_cli("--config", str(self.config()), "--fail-on", "patched").returncode, 2)
        self.assertEqual(self.run_cli("--bogus").returncode, 2)
        self.assertFalse(self.out.exists())

    def test_version(self) -> None:
        r = self.run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertRegex(r.stdout, r"^debian-security-readback \d+\.\d+\.\d+")

    def test_docker_behind_its_tag(self) -> None:
        executable(
            self.bin / "docker",
            "#!/bin/sh\n"
            'case "$1 $2" in\n'
            '  "ps -q") echo c1 ;;\n'
            '  "inspect --format") printf "/web\\tnginx:1\\tsha256:old\\n" ;;\n'
            '  "image inspect") echo sha256:new ;;\n'
            "esac\n",
        )
        r = self.run_cli("--config", str(self.config(docker="true")))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            self.report()["docker_stale"],
            [{"name": "web", "image": "nginx:1", "image_id": "sha256:old", "current_id": "sha256:new"}],
        )

    def test_missing_dpkg_is_a_failure_not_a_clean_host(self) -> None:
        (self.bin / "dpkg-query").write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        r = self.run_cli("--config", str(self.config()))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.report()["signature"], "failed")

    def test_apt_failing_fails_the_readback(self) -> None:
        for tool in ("apt-cache", "apt-mark"):
            with self.subTest(tool=tool):
                saved = (self.bin / tool).read_text(encoding="utf-8")
                (self.bin / tool).write_text("#!/bin/sh\necho 'E: broken' >&2\nexit 100\n", encoding="utf-8")
                r = self.run_cli("--config", str(self.config()))
                (self.bin / tool).write_text(saved, encoding="utf-8")
                self.assertEqual(r.returncode, 1)
                self.assertIn("%s exited 100" % tool, r.stderr)
                self.assertEqual(self.report()["signature"], "failed")

    def test_commands_run_in_the_c_locale(self) -> None:
        executable(
            self.bin / "apt-cache",
            '#!/bin/sh\nshift\nfor p in "$@"; do\n  echo "$p:"\n'
            '  if [ "$LC_ALL" = C ]; then label="Candidate:"; else label="Candidat :"; fi\n'
            '  case "$p" in gpgme1.0) echo "  $label 1.24.2-3+deb13u1" ;; *) echo "  $label (none)" ;; esac\ndone\n',
        )
        r = self.run_cli("--config", str(self.config()), LC_ALL="fr_FR.UTF-8", LANG="fr_FR.UTF-8")
        self.assertEqual(r.returncode, 0, r.stderr)
        fixes = self.report()["fixes"]
        assert isinstance(fixes, list)
        self.assertIn(("gpgme1.0", "available"), {(f["source"], f["state"]) for f in fixes})

    def test_a_command_that_hangs_times_out(self) -> None:
        executable(self.bin / "apt-mark", "#!/bin/sh\nexec sleep 30\n")
        start = time.monotonic()
        r = self.run_cli("--config", str(self.config(command_timeout_seconds="1")))
        self.assertEqual(r.returncode, 1)
        self.assertIn("apt-mark did not answer in 1 s", r.stderr)
        self.assertLess(time.monotonic() - start, 15)

    @unittest.skipIf(os.geteuid() == 0, "runs as root")
    def test_not_root_is_noted(self) -> None:
        self.assertEqual(self.run_cli("--config", str(self.config())).returncode, 0)
        notes = self.report()["notes"]
        assert isinstance(notes, list)
        self.assertTrue(any("not run as root" in n for n in notes), notes)

    def test_a_second_run_leaves_the_first_alone(self) -> None:
        (self.dir / "cache").mkdir()
        self.out.mkdir()
        (self.out / "report.json").write_text('{"signature": "first"}', encoding="utf-8")
        with exclusive_lock(str(self.dir / "cache" / "lock")):
            r = self.run_cli("--config", str(self.config()))
        self.assertEqual(r.returncode, 1)
        self.assertIn("another readback is running", r.stderr)
        self.assertEqual(self.report()["signature"], "first")

    def test_an_unsafe_directory_is_refused(self) -> None:
        self.out.mkdir()
        self.out.chmod(0o777)
        r = self.run_cli("--config", str(self.config()))
        self.assertEqual(r.returncode, 1)
        self.assertIn("writable by group or others", r.stderr)
        self.assertFalse((self.out / "report.json").exists())

    def test_report_modes(self) -> None:
        self.assertEqual(self.run_cli("--config", str(self.config())).returncode, 0)
        self.assertEqual(stat.S_IMODE((self.out / "report.json").stat().st_mode), 0o640)
        self.assertEqual(self.run_cli("--config", str(self.config(report_mode="0o600"))).returncode, 0)
        self.assertEqual(stat.S_IMODE((self.out / "report.md").stat().st_mode), 0o600)

    def test_a_release_without_dsas_says_so(self) -> None:
        r = self.run_cli("--config", str(self.config()), "--release", "forky")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no fixes for forky", r.stderr)


@unittest.skipUnless(os.path.exists("/proc/self/maps"), "needs Linux /proc")
class Proc(unittest.TestCase):
    def test_a_process_running_a_deleted_file_is_found(self) -> None:
        from debian_security_readback.collect import collect_processes

        with tempfile.TemporaryDirectory() as d:
            exe = Path(d) / "usr" / "bin" / "sleeper"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(Path("/bin/sleep").read_bytes())
            exe.chmod(0o755)
            p = subprocess.Popen([str(exe), "30"])
            try:
                exe.unlink()
                found = [x for x in collect_processes("/proc", ()) if x["pid"] == str(p.pid)]
            finally:
                p.kill()
                p.wait()
        self.assertEqual(len(found), 1)
        # the deleted file is not under a code prefix (it lives in a temporary directory), but a
        # deleted executable always counts
        self.assertEqual(found[0]["paths"], [str(exe)])


if __name__ == "__main__":
    unittest.main()
