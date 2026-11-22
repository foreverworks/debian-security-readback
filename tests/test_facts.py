import unittest

from debian_security_readback.facts import (
    in_container,
    incus_images,
    incus_instances,
    kernel_state,
    parse_apt_policy,
    parse_docker_inspect,
    parse_installed,
    parse_maps_deleted,
    parse_os_release,
    parse_owners,
    pending_packages,
)
from debian_security_readback.model import Process
from tests.support import pkg


class Dpkg(unittest.TestCase):
    def test_installed_skips_removed_packages(self) -> None:
        out = "a:amd64\t1\ta\t1\tii \nb\t2\tb\t2\trc \nc\t1\tc\t1\tun \nshort\nd\t1\td\t1\t\n"
        self.assertEqual([p["name"] for p in parse_installed(out)], ["a"])

    def test_held_and_half_done_packages_are_installed(self) -> None:
        # `apt-mark hold` makes the status `hi`; a failed upgrade leaves `iF` or `iU`.
        out = "held\t1\theld\t1\thi \nhalf\t1\thalf\t1\tiF \nunpacked\t1\tu\t1\tiU \n"
        self.assertEqual([p["name"] for p in parse_installed(out)], ["held", "half", "unpacked"])

    def test_owners_and_pending(self) -> None:
        owners = parse_owners(
            "libssl3t64:amd64: /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
            "libfoo1, libfoo-dev: /usr/lib/libfoo.so.1\n"
            "dpkg-query: no path found matching pattern /x\n"
        )
        self.assertEqual(owners, {"/usr/lib/x86_64-linux-gnu/libssl.so.3": "libssl3t64", "/usr/lib/libfoo.so.1": "libfoo1"})
        procs: list[Process] = [{"pid": "7", "comm": "sshd", "paths": ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]}]
        self.assertEqual(pending_packages(procs, owners), {"libssl3t64": ["sshd(7)"]})

    def test_apt_policy(self) -> None:
        text = (
            "libfoo1:\n  Installed: 1.0-1\n  Candidate: 1.0-2\n  Version table:\n"
            "libbar:amd64:\n  Installed: 2-1\n  Candidate: (none)\n"
        )
        self.assertEqual(parse_apt_policy(text), {"libfoo1": "1.0-2"})

    def test_os_release(self) -> None:
        info = parse_os_release('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=trixie\n# x\n')
        self.assertEqual((info["ID"], info["VERSION_CODENAME"]), ("debian", "trixie"))


class Kernel(unittest.TestCase):
    def test_kernel_state_from_packages(self) -> None:
        inst = [
            pkg("linux-image-6.12.60-amd64", "6.12.60-1", "linux-signed-amd64"),
            pkg("linux-image-6.12.70-amd64", "6.12.70-1", "linux-signed-amd64"),
            pkg("linux-image-amd64", "6.12.70-1", "linux-signed-amd64"),
        ]
        k = kernel_state(inst, "6.12.60-amd64")
        self.assertEqual((k["installed"], k["running"]), ("6.12.70-1", "6.12.60-1"))
        self.assertEqual(kernel_state([], "6.1.0")["installed"], None)


class Proc(unittest.TestCase):
    def test_deleted_maps_real_files_only(self) -> None:
        maps = (
            "7f00-7f10 r-xp 00000000 08:01 12 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"
            "7f20-7f30 rw-s 00000000 00:01 3 /memfd:x (deleted)\n"
            "7f30-7f38 rw-s 00000000 00:01 4 /dev/shm/x (deleted)\n"
            "7f40-7f50 r-xp 00000000 08:01 13 /usr/lib/libc.so.6\n"
        )
        self.assertEqual(parse_maps_deleted(maps), {"/usr/lib/x86_64-linux-gnu/libssl.so.3"})

    def test_container_cgroups_are_excluded(self) -> None:
        cid = "3f4e" * 16
        for path in (
            "/system.slice/docker-%s.scope" % cid,
            "/docker/%s" % cid,
            "/machine.slice/libpod-%s.scope/container" % cid,
            "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-%s.scope/container" % cid,
            "/libpod_parent/libpod-%s" % cid,
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-%s.scope" % cid,
            "/kubepods/besteffort/pod1234/%s" % cid,
            "/system.slice/crio-%s.scope" % cid,
            "/lxc.payload.web1/system.slice/nginx.service",
            "/machine.slice/systemd-nspawn@build.service/payload/system.slice/cron.service",
            "/machine.slice/machine-build.scope/payload",
        ):
            self.assertTrue(in_container("0::%s\n" % path), path)
        # cgroup v1: any hierarchy's path counts
        self.assertTrue(in_container("12:pids:/docker/%s\n11:cpu,cpuacct:/docker/%s\n" % (cid, cid)))

    def test_host_services_are_not_containers(self) -> None:
        cid = "3f4e" * 16
        for path in (
            "/system.slice/ssh.service",
            "/system.slice/docker.service",  # dockerd itself
            "/system.slice/containerd.service",
            "/system.slice/incus.service",
            "/system.slice/docker-compose-app.service",
            "/system.slice/docker-cleanup.timer",
            "/system.slice/libpod-conmon-%s.scope" % cid,  # Podman's monitor runs on the host
            "/system.slice/crio-conmon-%s.scope" % cid,
            "/lxc.monitor.web1",  # Incus's monitor of a container
            "/machine.slice/machine-qemu\\x2d1\\x2dvm1.scope/libvirt/emulator",  # a VM's qemu
            "/user.slice/user-1000.slice/session-3.scope",
            "/",
        ):
            self.assertFalse(in_container("0::%s\n" % path), path)
        self.assertTrue(in_container("0::/system.slice/myruntime-1.scope\n", (r"(^|/)myruntime-\d+\.scope$",)))
        self.assertFalse(in_container("0::/system.slice/docker-%s.scope\n" % cid, ()))


class Containers(unittest.TestCase):
    def test_docker_inspect(self) -> None:
        out = parse_docker_inspect("/web\tnginx:1\tsha256:aa\nbroken\n")
        self.assertEqual(out, [{"name": "web", "image": "nginx:1", "image_id": "sha256:aa"}])

    def test_incus_listing(self) -> None:
        cfg = {"volatile.base_image": "aaa", "image.os": "debian", "image.release": "trixie", "image.serial": "20261101"}
        listing = [
            {"name": "i", "project": "default", "status": "Running", "config": cfg},
            {"name": "j", "project": "default", "status": "Stopped", "config": cfg},
            {"name": "k", "status": "Running", "config": {}},
            "junk",
        ]
        rows = incus_instances(listing)
        self.assertEqual([(r["name"], r["fingerprint"], r["serial"]) for r in rows], [("i", "aaa", "20261101")])
        imgs = incus_images([{"fingerprint": "bbb", "properties": {"os": "debian", "serial": 20261120}}, 3])
        self.assertEqual((imgs[0]["fingerprint"], imgs[0]["serial"]), ("bbb", "20261120"))
        self.assertEqual(incus_instances({"not": "a list"}), [])


if __name__ == "__main__":
    unittest.main()
