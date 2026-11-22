"""The edge: gather the facts. Read-only: nothing here installs, restarts or removes anything."""

import json
import os
import subprocess
import time
import urllib.parse
import urllib.request
from collections.abc import Callable

from debian_security_readback import __version__
from debian_security_readback.decide import stale_docker, stale_incus
from debian_security_readback.facts import (
    DPKG_FORMAT,
    in_container,
    incus_images,
    incus_instances,
    parse_apt_policy,
    parse_docker_inspect,
    parse_installed,
    parse_maps_deleted,
    parse_owners,
    pending_packages,
)
from debian_security_readback.model import Package, Process, ReadbackError, StaleDocker, StaleIncus

SOCKET_TIMEOUT_S = 60


class ToolError(Exception):
    """A command that had to succeed did not."""


def run(cmd: list[str], check: bool = False) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and r.returncode:
        raise ToolError("%s: %s" % (" ".join(cmd), r.stderr.strip()))
    return r.stdout


def fetch(url: str, dest: str, check: Callable[[str], None], max_age_s: float, deadline_s: float) -> tuple[str, str]:
    """`url` downloaded to `dest`, unless `dest` is younger than max_age_s. A download that fails,
    takes longer than deadline_s or does not pass `check` (a callable on the path that raises
    ReadbackError) never replaces the cached copy; a stale cached copy is used instead. Returns
    (path, note), where the note says so, or is empty."""
    if os.path.exists(dest) and time.time() - os.path.getmtime(dest) < max_age_s:
        return dest, ""
    tmp = dest + ".tmp"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "debian-security-readback/" + __version__})
        start = time.time()
        with urllib.request.urlopen(req, timeout=SOCKET_TIMEOUT_S) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
                if time.time() - start > deadline_s:
                    raise ReadbackError("download took longer than %d s" % deadline_s)
        check(tmp)
        os.replace(tmp, dest)
        return dest, ""
    except (OSError, ReadbackError, ValueError) as e:
        if os.path.exists(tmp):
            os.unlink(tmp)
        if not os.path.exists(dest):
            raise ReadbackError("%s: %s, and no cached copy" % (url, e)) from e
        age = int((time.time() - os.path.getmtime(dest)) / 3600)
        where = urllib.parse.urlparse(url).netloc or url
        return dest, "%s could not be refreshed (%s): using a copy %d h old" % (where, e, age)


def collect_installed() -> list[Package]:
    return parse_installed(run(["dpkg-query", "-W", "-f", DPKG_FORMAT], check=True))


def collect_holds() -> set[str]:
    return set(run(["apt-mark", "showhold"], check=True).split())


def collect_candidates(names: list[str]) -> dict[str, str]:
    cands: dict[str, str] = {}
    for i in range(0, len(names), 200):
        cands.update(parse_apt_policy(run(["apt-cache", "policy", *names[i : i + 200]])))
    return cands


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def collect_processes(proc_root: str, markers: tuple[str, ...]) -> list[Process]:
    """The host's processes (containers left out by cgroup) that map a deleted file or run a deleted
    binary."""
    procs: list[Process] = []
    for pid in sorted((d for d in os.listdir(proc_root) if d.isdigit()), key=int):
        d = os.path.join(proc_root, pid)
        try:
            if in_container(_read(d + "/cgroup"), markers):
                continue
            paths = parse_maps_deleted(_read(d + "/maps"))
        except OSError:
            continue  # gone, or not ours to read
        try:
            exe = os.readlink(d + "/exe")
            if exe.endswith(" (deleted)"):
                paths.add(exe[: -len(" (deleted)")])
        except OSError:
            pass  # a kernel thread
        if paths:
            try:
                comm = _read(d + "/comm").strip()
            except OSError:
                continue
            procs.append({"pid": pid, "comm": comm, "paths": sorted(paths)})
    return procs


def collect_pending(proc_root: str, markers: tuple[str, ...]) -> dict[str, list[str]]:
    procs = collect_processes(proc_root, markers)
    allpaths = sorted({x for p in procs for x in p["paths"]})
    owners: dict[str, str] = {}
    for i in range(0, len(allpaths), 100):
        owners.update(parse_owners(run(["dpkg-query", "-S", *allpaths[i : i + 100]])))
    return pending_packages(procs, owners)


def collect_docker() -> list[StaleDocker] | None:
    """None when Docker is not there or does not answer."""
    try:
        ids = run(["docker", "ps", "-q"], check=True).split()
    except (OSError, ToolError):
        return None
    if not ids:
        return []
    running = parse_docker_inspect(run(["docker", "inspect", "--format", "{{.Name}}\t{{.Config.Image}}\t{{.Image}}", *ids]))
    current: dict[str, str] = {}
    for image in sorted({c["image"] for c in running}):
        out = run(["docker", "image", "inspect", "--format", "{{.Id}}", image]).strip()
        if out:
            current[image] = out
    return stale_docker(running, current)


def collect_incus() -> list[StaleIncus] | None:
    """None when Incus is not there or does not answer."""
    try:
        insts: object = json.loads(run(["incus", "list", "--all-projects", "--format", "json"], check=True) or "[]")
        images: object = json.loads(run(["incus", "image", "list", "--all-projects", "--format", "json"], check=True) or "[]")
    except (OSError, ToolError, ValueError):
        return None
    return stale_incus(incus_instances(insts), incus_images(images))
