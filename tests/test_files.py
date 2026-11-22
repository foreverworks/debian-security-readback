import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from debian_security_readback.collect import collect_processes
from debian_security_readback.files import (
    LockBusyError,
    UnsafeDirError,
    exclusive_lock,
    remove_stale_temporaries,
    safe_dir,
    write_text,
)


class Files(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_safe_dir(self) -> None:
        d = self.dir / "a" / "b"
        safe_dir(str(d))
        self.assertTrue(d.is_dir())
        d.chmod(0o775)
        with self.assertRaisesRegex(UnsafeDirError, "writable by group or others"):
            safe_dir(str(d))
        d.chmod(0o755)
        link = self.dir / "link"
        link.symlink_to(d)
        with self.assertRaisesRegex(UnsafeDirError, "symlink"):
            safe_dir(str(link))
        with mock.patch("os.geteuid", return_value=os.geteuid() + 4242), self.assertRaisesRegex(UnsafeDirError, "belongs to"):
            safe_dir(str(d))

    def test_writes_never_follow_a_symlink_and_set_the_mode(self) -> None:
        victim = self.dir / "victim"
        victim.write_text("keep\n", encoding="utf-8")
        target = self.dir / "report.json"
        target.symlink_to(victim)
        write_text(str(target), 0o640, "new\n")
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep\n")
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["report.json", "victim"])

    def test_a_killed_runs_temporaries_are_removed(self) -> None:
        for name in (".tracker.json.k3j9x_a1", ".tracker.json.zz", ".report.md.q", "tracker.json", ".other.x", "keep"):
            (self.dir / name).write_text("x", encoding="utf-8")
        remove_stale_temporaries(str(self.dir / "tracker.json"))
        remove_stale_temporaries(str(self.dir / "report.md"))
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [".other.x", "keep", "tracker.json"])

    def test_one_run_at_a_time(self) -> None:
        lock = str(self.dir / "lock")
        with exclusive_lock(lock), self.assertRaises(LockBusyError), exclusive_lock(lock):
            pass
        with exclusive_lock(lock):
            pass


class FakeProc(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.proc = Path(tmp.name)

    def pid(self, pid: str, cgroup: str | None, maps: str | None, comm: str = "x", exe: str | None = None) -> Path:
        d = self.proc / pid
        d.mkdir()
        for name, text in (("cgroup", cgroup), ("maps", maps), ("comm", comm + "\n")):
            if text is not None:
                (d / name).write_text(text, encoding="utf-8")
        if exe is not None:
            (d / "exe").symlink_to(exe)
        return d

    def test_scan(self) -> None:
        deleted = "7f00-7f10 r-xp 00000000 08:01 12 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"
        self.pid("100", "0::/system.slice/nginx.service\n", deleted, "nginx", "/usr/sbin/nginx")
        self.pid("101", "0::/system.slice/docker-%s.scope\n" % ("ab" * 32), deleted, "inside")
        self.pid("102", None, None)  # gone while being read
        self.pid("104", "0::/system.slice/old.service\n", "", "old", "/usr/bin/old (deleted)")
        self.pid("105", "0::/system.slice/fine.service\n", "", "fine", "/usr/bin/fine")
        (self.proc / "self").mkdir()
        unreadable = self.pid("103", "0::/system.slice/secret.service\n", deleted, "secret")
        (unreadable / "maps").chmod(0)
        found = {
            p["pid"]: (p["comm"], p["paths"]) for p in collect_processes(str(self.proc), ("(^|/)docker-[0-9a-f]{64}\\.scope",))
        }
        want = {
            "100": ("nginx", ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]),
            "104": ("old", ["/usr/bin/old"]),
        }
        if os.geteuid() == 0:  # root reads a mode-0 file anyway
            want["103"] = ("secret", ["/usr/lib/x86_64-linux-gnu/libssl.so.3"])
        self.assertEqual(found, want)


if __name__ == "__main__":
    unittest.main()
