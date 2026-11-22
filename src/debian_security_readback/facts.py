"""What the host says: dpkg, apt, /proc, Docker and Incus output, parsed. Pure: text in, data out."""

import re

from debian_security_readback.debversion import compare_versions
from debian_security_readback.model import (
    DockerContainer,
    IncusImage,
    IncusInstance,
    Kernel,
    Package,
    Process,
)

# The dpkg-query format parse_installed() reads.
DPKG_FORMAT = "${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"

# Where a deleted file must live to count: the places packages install code to.
CODE_PREFIXES = ("/usr/", "/lib", "/opt/", "/bin/", "/sbin/")

# Regular expressions searched in each cgroup path of /proc/<pid>/cgroup that mark a process of a
# container: its files are the container's, not the host's. Each one matches whole path components,
# so a host service such as docker.service, incus.service or docker-compose-app.service is not one,
# and neither are the runtimes' own monitors (conmon, lxc.monitor) or a virtual machine's emulator.
DEFAULT_CONTAINER_PATTERNS = (
    r"(^|/)docker-[0-9a-f]{64}\.scope(/|$)",  # Docker, systemd cgroup driver
    r"(^|/)docker/[0-9a-f]{64}(/|$)",  # Docker, cgroupfs driver
    r"(^|/)libpod-[0-9a-f]{64}\.scope(/|$)",  # Podman
    r"(^|/)libpod_parent/libpod-[0-9a-f]{64}(/|$)",  # Podman, cgroupfs driver
    r"(^|/)crio-[0-9a-f]{64}\.scope(/|$)",  # CRI-O
    r"(^|/)cri-containerd-[0-9a-f]{64}\.scope(/|$)",  # containerd under Kubernetes
    r"(^|/)kubepods[^/]*(/|$)",  # every pod of a Kubernetes node
    r"(^|/)lxc\.payload\.[^/]+(/|$)",  # Incus, LXD and LXC containers
    r"(^|/)machine\.slice/[^/]+/payload(/|$)",  # systemd-nspawn containers
)


def parse_os_release(text: str) -> dict[str, str]:
    """/etc/os-release as {key: value}, quotes removed."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            out[key] = value.strip().strip("\"'")
    return out


def parse_installed(dpkg_output: str) -> list[Package]:
    """`dpkg-query -W -f DPKG_FORMAT` output -> the packages with files on disk.

    The status's first letter is what was asked for (`i` install, `h` hold, `r` remove...), the second
    what is there: everything but `n` (not installed) and `c` (configuration files only) has code on
    disk. A held package (`hi`) is installed: leaving it out would hide exactly the fixes a hold blocks."""
    out: list[Package] = []
    for line in dpkg_output.splitlines():
        f = line.split("\t")
        if len(f) < 5 or len(f[4]) < 2 or f[4][1] in "nc":
            continue
        out.append({"name": f[0].split(":")[0], "version": f[1], "source": f[2], "source_version": f[3]})
    return out


def kernel_state(installed: list[Package], uname_r: str) -> Kernel:
    """The versions of the installed linux-image-* packages (source package `linux`, possibly signed):
    the newest one, and the one of the running kernel."""
    images = {p["name"]: p["version"] for p in installed if re.match(r"^linux-image-\d", p["name"])}
    newest: str | None = None
    for v in images.values():
        if newest is None or compare_versions(v, newest) > 0:
            newest = v
    return {"installed": newest, "running": images.get("linux-image-" + uname_r), "release": uname_r}


def parse_apt_policy(text: str) -> dict[str, str]:
    """`apt-cache policy <names>` -> {name: candidate version}; packages without one are left out."""
    cands: dict[str, str] = {}
    name: str | None = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.rstrip(":").split(":")[0]
        elif name and line.strip().startswith("Candidate:"):
            v = line.split(":", 1)[1].strip()
            if v != "(none)":
                cands[name] = v
    return cands


def parse_maps_deleted(maps_text: str) -> set[str]:
    """The files a /proc/<pid>/maps text maps that no longer exist on disk (real files only)."""
    paths: set[str] = set()
    for line in maps_text.splitlines():
        if not line.endswith(" (deleted)"):
            continue
        parts = line[: -len(" (deleted)")].split(None, 5)
        if len(parts) == 6 and parts[5].startswith(CODE_PREFIXES):
            paths.add(parts[5])
    return paths


def cgroup_paths(cgroup_text: str) -> list[str]:
    """The paths of a /proc/<pid>/cgroup text, cgroup v2 (`0::/path`) and v1 (`4:pids:/path`) alike."""
    return [line.split(":", 2)[2] for line in cgroup_text.splitlines() if line.count(":") >= 2]


def in_container(cgroup_text: str, patterns: tuple[str, ...] = DEFAULT_CONTAINER_PATTERNS) -> bool:
    """True for a process of a container. A host service with a private mount namespace is not one."""
    compiled = [re.compile(p) for p in patterns]
    return any(c.search(path) for path in cgroup_paths(cgroup_text) for c in compiled)


def parse_owners(dpkg_s_output: str) -> dict[str, str]:
    """`dpkg-query -S <paths>` output -> {path: package}."""
    owners: dict[str, str] = {}
    for line in dpkg_s_output.splitlines():
        m = re.match(r"^([^:\s]+)(?::\w+)?(?:, [^:]+)*: (/.*)$", line)
        if m:
            owners[m.group(2)] = m.group(1)
    return owners


def pending_packages(procs: list[Process], owners: dict[str, str]) -> dict[str, list[str]]:
    """{package: ['comm(pid)', ...]}: the processes that still run a package's deleted files."""
    out: dict[str, list[str]] = {}
    for p in procs:
        for pkg in sorted({owners[x] for x in p["paths"] if x in owners}):
            out.setdefault(pkg, []).append("%s(%s)" % (p["comm"], p["pid"]))
    return out


def parse_docker_inspect(text: str) -> list[DockerContainer]:
    """`docker inspect --format '{{.Name}}\\t{{.Config.Image}}\\t{{.Image}}' <ids>` output."""
    out: list[DockerContainer] = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) == 3:
            out.append({"name": f[0].lstrip("/"), "image": f[1], "image_id": f[2]})
    return out


def _props(obj: dict[object, object], key: str) -> dict[object, object]:
    v = obj.get(key)
    return v if isinstance(v, dict) else {}


def _s(d: dict[object, object], key: str) -> str:
    v = d.get(key)
    return "" if v is None else str(v)


def incus_instances(listing: object) -> list[IncusInstance]:
    """`incus list --all-projects --format json` -> the running instances with a known base image."""
    out: list[IncusInstance] = []
    for o in listing if isinstance(listing, list) else []:
        if not isinstance(o, dict) or o.get("status") != "Running":
            continue
        c = _props(o, "config")
        row: IncusInstance = {
            "name": _s(o, "name"),
            "project": _s(o, "project"),
            "fingerprint": _s(c, "volatile.base_image"),
            "os": _s(c, "image.os"),
            "release": _s(c, "image.release"),
            "arch": _s(c, "image.architecture"),
            "variant": _s(c, "image.variant"),
            "serial": _s(c, "image.serial"),
        }
        if row["fingerprint"] and row["serial"]:
            out.append(row)
    return out


def incus_images(listing: object) -> list[IncusImage]:
    """`incus image list --all-projects --format json` -> the local images."""
    out: list[IncusImage] = []
    for m in listing if isinstance(listing, list) else []:
        if not isinstance(m, dict):
            continue
        p = _props(m, "properties")
        out.append(
            {
                "fingerprint": _s(m, "fingerprint"),
                "os": _s(p, "os"),
                "release": _s(p, "release"),
                "arch": _s(p, "architecture"),
                "variant": _s(p, "variant"),
                "serial": _s(p, "serial"),
            }
        )
    return out
