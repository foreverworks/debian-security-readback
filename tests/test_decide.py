import unittest
from collections.abc import Iterable
from typing import ClassVar

from debian_security_readback.decide import (
    classify,
    fix_state,
    relevant_packages,
    signature,
    stale_docker,
    stale_incus,
)
from debian_security_readback.model import DockerContainer, Fix, IncusImage, IncusInstance, Kernel, Package, Row, State
from debian_security_readback.sources import parse_dsa_list
from tests.support import DSA, NOKERNEL, TODAY, fix, pkg


def state(
    binaries: list[Package],
    cands: dict[str, str] | None = None,
    holds: Iterable[str] = (),
    pending: dict[str, list[str]] | None = None,
    f: Fix | None = None,
    kernel: Kernel = NOKERNEL,
) -> State:
    res = fix_state(f or fix(), binaries, cands or {}, set(holds), pending or {}, kernel)
    assert res is not None
    return res[0]


class States(unittest.TestCase):
    def test_not_installed_is_not_concerned(self) -> None:
        self.assertIsNone(fix_state(fix(), [], {}, set(), {}, NOKERNEL))

    def test_available(self) -> None:
        self.assertEqual(state([pkg("gpgme1.0", "1.0-1")], {"gpgme1.0": "1.24.2-3+deb13u1"}), "available")

    def test_held_is_blocked_even_when_installable(self) -> None:
        self.assertEqual(state([pkg("gpgme1.0", "1.0-1")], {"gpgme1.0": "1.24.2-3+deb13u1"}, holds=["gpgme1.0"]), "blocked")

    def test_missing_from_the_archive_is_blocked(self) -> None:
        self.assertEqual(state([pkg("gpgme1.0", "1.0-1")], {"gpgme1.0": "1.0-1"}), "blocked")
        self.assertEqual(state([pkg("gpgme1.0", "1.0-1")]), "blocked")

    def test_one_old_binary_keeps_the_fix_from_being_patched(self) -> None:
        b = [pkg("libgpgme11", "1.24.2-3+deb13u1", "gpgme1.0"), pkg("libgpgme-dev", "1.0-1", "gpgme1.0")]
        self.assertEqual(state(b, {"libgpgme-dev": "1.0-1"}, holds=["libgpgme-dev"]), "blocked")

    def test_installed_with_stale_process_is_pending(self) -> None:
        b = [pkg("gpgme1.0", "1.24.2-3+deb13u1")]
        self.assertEqual(state(b, pending={"gpgme1.0": ["gpg(1)"]}), "installed_pending_activation")

    def test_many_stale_processes_are_cut_short(self) -> None:
        b = [pkg("gpgme1.0", "1.24.2-3+deb13u1")]
        res = fix_state(fix(), b, {}, set(), {"gpgme1.0": ["p(%d)" % i for i in range(10)]}, NOKERNEL)
        assert res is not None
        self.assertTrue(res[1].endswith("(+2)"), res[1])

    def test_installed_clean_is_active(self) -> None:
        self.assertEqual(state([pkg("gpgme1.0", "1.24.2-3+deb13u2")]), "active")

    def test_held_package_with_a_stale_process_is_never_active(self) -> None:
        b = [pkg("gpgme1.0", "1.0-1")]
        s = state(b, {"gpgme1.0": "1.24.2-3+deb13u1"}, holds=["gpgme1.0"], pending={"gpgme1.0": ["x(1)"]})
        self.assertNotEqual(s, "active")


class KernelFixes(unittest.TestCase):
    f: ClassVar[Fix] = {"source": "linux", "fixed_version": "6.12.70-1", "dsa": "DSA-1", "date": "2026-11-19", "cves": []}

    def kstate(self, installed: str, running: str, cands: dict[str, str] | None = None) -> State | None:
        k: Kernel = {"installed": installed, "running": running, "release": "6.12.x"}
        res = fix_state(self.f, [], cands or {}, set(), {}, k)
        return None if res is None else res[0]

    def test_states(self) -> None:
        self.assertEqual(self.kstate("6.12.70-1", "6.12.70-1"), "active")
        self.assertEqual(self.kstate("6.12.70-1", "6.12.60-1"), "installed_pending_activation")
        self.assertEqual(self.kstate("6.12.60-1", "6.12.60-1", {"linux-image-6.12.70-amd64": "6.12.70-1"}), "available")
        self.assertEqual(self.kstate("6.12.60-1", "6.12.60-1"), "blocked")

    def test_held_kernel_is_blocked_not_available(self) -> None:
        k: Kernel = {"installed": "6.12.60-1", "running": "6.12.60-1", "release": "x"}
        res = fix_state(self.f, [], {"linux-image-6.12.70-amd64": "6.12.70-1"}, {"linux-image-amd64"}, {}, k)
        self.assertEqual(res and res[0], "blocked")

    def test_no_kernel_package_is_not_concerned(self) -> None:
        # a container, or a host booted from a kernel no package installed
        self.assertIsNone(fix_state(self.f, [], {}, set(), {}, NOKERNEL))


class Containers(unittest.TestCase):
    def test_docker(self) -> None:
        run: list[DockerContainer] = [
            {"name": "a", "image": "x:1", "image_id": "sha256:old"},
            {"name": "b", "image": "y:1", "image_id": "sha256:y"},
        ]
        out = stale_docker(run, {"x:1": "sha256:new", "y:1": "sha256:y"})
        self.assertEqual([(c["name"], c["current_id"]) for c in out], [("a", "sha256:new")])

    def test_incus(self) -> None:
        def image(fp: str, serial: str) -> IncusImage:
            return {"os": "debian", "release": "trixie", "arch": "amd64", "variant": "cloud", "fingerprint": fp, "serial": serial}

        inst: list[IncusInstance] = [{**image("aaa", "20261101"), "name": "i", "project": "default"}]
        imgs: list[IncusImage] = [
            image("aaa", "20261101"),
            image("bbb", "20261120"),
            {**image("ccc", "20261130"), "variant": "default"},
        ]
        self.assertEqual(stale_incus(inst, imgs)[0]["newer"], "bbb")
        self.assertEqual(stale_incus(inst, imgs[:1]), [])


class Classify(unittest.TestCase):
    def test_rows_and_order(self) -> None:
        installed = [pkg("gpgme1.0", "1.0-1")]
        rows = classify(parse_dsa_list(DSA, "trixie"), installed, {}, set(), {}, NOKERNEL, {}, TODAY)
        self.assertEqual([(r["state"], r["dsa"], r["age_days"]) for r in rows], [("blocked", "DSA-6646-1", 1)])
        self.assertEqual(relevant_packages(parse_dsa_list(DSA, "trixie"), installed), ["gpgme1.0"])

    def test_signature_ignores_active_rows(self) -> None:
        a: list[Row] = [
            {
                "state": "active",
                "dsa": "D1",
                "source": "p",
                "reason": "",
                "date": "2026-11-01",
                "age_days": 1,
                "fixed_version": "1",
                "cves": [],
                "urgency": "low",
            }
        ]
        self.assertEqual(signature(a), signature([]))
        self.assertNotEqual(signature([{**a[0], "state": "blocked"}]), signature([]))


if __name__ == "__main__":
    unittest.main()
