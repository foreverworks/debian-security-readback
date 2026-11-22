"""The edge: gather the facts. Read-only: nothing here installs, restarts or removes anything."""

import json
import os
import subprocess

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
from debian_security_readback.model import Package, Process, StaleDocker, StaleIncus

COMMAND_TIMEOUT_S = 120.0


class ToolError(Exception):
    """A command that had to succeed did not, or did not answer in time."""


def run(cmd: list[str], check: bool = False, timeout: float = COMMAND_TIMEOUT_S) -> str:
    """The command's standard output. It runs in the C locale, because the output is parsed: a
    translated `apt-cache policy` says "Candidat :" and every fix would read as blocked."""
    env = {**os.environ, "LC_ALL": "C"}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as e:
        raise ToolError("%s did not answer in %g s" % (cmd[0], timeout)) from e
    if check and r.returncode:
        raise ToolError("%s exited %d: %s" % (cmd[0], r.returncode, r.stderr.strip()[-500:]))
    return r.stdout


def collect_installed(timeout: float = COMMAND_TIMEOUT_S) -> list[Package]:
    return parse_installed(run(["dpkg-query", "-W", "-f", DPKG_FORMAT], check=True, timeout=timeout))


def collect_holds(timeout: float = COMMAND_TIMEOUT_S) -> set[str]:
    return set(run(["apt-mark", "showhold"], check=True, timeout=timeout).split())


def collect_candidates(names: list[str], timeout: float = COMMAND_TIMEOUT_S) -> dict[str, str]:
    cands: dict[str, str] = {}
    for i in range(0, len(names), 200):
        cands.update(parse_apt_policy(run(["apt-cache", "policy", *names[i : i + 200]], check=True, timeout=timeout)))
    return cands


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def collect_processes(proc_root: str, patterns: tuple[str, ...]) -> list[Process]:
    """The host's processes (containers left out by cgroup) that map a deleted file or run a deleted
    binary."""
    procs: list[Process] = []
    for pid in sorted((d for d in os.listdir(proc_root) if d.isdigit()), key=int):
        d = os.path.join(proc_root, pid)
        try:
            if in_container(_read(d + "/cgroup"), patterns):
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


def collect_pending(proc_root: str, patterns: tuple[str, ...], timeout: float = COMMAND_TIMEOUT_S) -> dict[str, list[str]]:
    """{package: processes}. dpkg-query -S exits 1 when one of the paths belongs to no package, so its
    exit status cannot tell a failure from that: a path it does not answer for is left out."""
    procs = collect_processes(proc_root, patterns)
    allpaths = sorted({x for p in procs for x in p["paths"]})
    owners: dict[str, str] = {}
    for i in range(0, len(allpaths), 100):
        owners.update(parse_owners(run(["dpkg-query", "-S", *allpaths[i : i + 100]], timeout=timeout)))
    return pending_packages(procs, owners)


def collect_docker(timeout: float = COMMAND_TIMEOUT_S) -> list[StaleDocker] | None:
    """None when Docker is not there or does not answer."""
    try:
        ids = run(["docker", "ps", "-q"], check=True, timeout=timeout).split()
    except (OSError, ToolError):
        return None
    if not ids:
        return []
    try:
        fmt = "{{.Name}}\t{{.Config.Image}}\t{{.Image}}"
        running = parse_docker_inspect(run(["docker", "inspect", "--format", fmt, *ids], timeout=timeout))
        current: dict[str, str] = {}
        for image in sorted({c["image"] for c in running}):
            out = run(["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=timeout).strip()
            if out:
                current[image] = out
    except ToolError:
        return None
    return stale_docker(running, current)


def collect_incus(timeout: float = COMMAND_TIMEOUT_S) -> list[StaleIncus] | None:
    """None when Incus is not there or does not answer."""
    try:
        insts: object = json.loads(
            run(["incus", "list", "--all-projects", "--format", "json"], check=True, timeout=timeout) or "[]"
        )
        images: object = json.loads(
            run(["incus", "image", "list", "--all-projects", "--format", "json"], check=True, timeout=timeout) or "[]"
        )
    except (OSError, ToolError, ValueError):
        return None
    return stale_incus(incus_instances(insts), incus_images(images))
