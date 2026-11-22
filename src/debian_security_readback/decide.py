"""The decision: one state per fix. Pure functions over the facts the edge gathered."""

import datetime
import hashlib

from debian_security_readback.debversion import compare_versions, version_key
from debian_security_readback.model import (
    STATES,
    DockerContainer,
    Fix,
    IncusImage,
    IncusInstance,
    Kernel,
    Package,
    Row,
    StaleDocker,
    StaleIncus,
    State,
    Urgencies,
)
from debian_security_readback.sources import fix_urgency


def relevant_packages(fixes: list[Fix], installed: list[Package]) -> list[str]:
    """The installed binary packages whose source package a fix names."""
    sources = {f["source"] for f in fixes}
    return sorted({p["name"] for p in installed if p["source"] in sources})


def _kernel_state(fixed: str, candidates: dict[str, str], holds: set[str], kernel: Kernel) -> tuple[State, str] | None:
    if kernel["installed"] is None:
        return None
    if compare_versions(kernel["installed"], fixed) < 0:
        held = sorted(h for h in holds if h.startswith("linux-image"))
        if held:
            return "blocked", "kernel on hold: " + ", ".join(held)
        offered = [v for n, v in candidates.items() if n.startswith("linux-image-")]
        cand = max(offered, key=version_key, default=None)
        if cand is None or compare_versions(cand, fixed) < 0:
            return "blocked", "no installable kernel at %s (archive offers %s)" % (fixed, cand)
        return "available", "kernel %s installable, installed %s" % (cand, kernel["installed"])
    if kernel["running"] is None or compare_versions(kernel["running"], fixed) < 0:
        return "installed_pending_activation", "running kernel %s older than %s; reboot pending" % (
            kernel["running"] or kernel["release"],
            fixed,
        )
    return "active", "running kernel %s" % kernel["running"]


def fix_state(
    fix: Fix,
    binaries: list[Package],
    candidates: dict[str, str],
    holds: set[str],
    pending: dict[str, list[str]],
    kernel: Kernel,
) -> tuple[State, str] | None:
    """One fix against this host -> (state, reason), or None when the fix does not concern it.

    binaries   the installed packages built from the fix's source package
    candidates {name: the version the archive offers here}
    holds      the packages on hold
    pending    {package: [processes]} still running its deleted files
    kernel     kernel_state()
    """
    fixed = fix["fixed_version"]
    if fix["source"] == "linux":
        return _kernel_state(fixed, candidates, holds, kernel)
    if not binaries:
        return None
    below = [b for b in binaries if compare_versions(b["source_version"], fixed) < 0]
    if below:
        held = [b["name"] for b in below if b["name"] in holds]
        if held:
            return "blocked", "on hold: " + ", ".join(sorted(held))
        short = [b["name"] for b in below if compare_versions(candidates.get(b["name"], b["source_version"]), fixed) < 0]
        if short:
            return "blocked", "archive offers no %s for: %s" % (fixed, ", ".join(sorted(short)))
        return "available", "installable: " + ", ".join(sorted(b["name"] for b in below))
    procs = sorted({p for b in binaries for p in pending.get(b["name"], [])})
    if procs:
        more = " (+%d)" % (len(procs) - 8) if len(procs) > 8 else ""
        return "installed_pending_activation", "stale processes: " + ", ".join(procs[:8]) + more
    return "active", "installed %s" % min((b["source_version"] for b in binaries), key=version_key)


def classify(
    fixes: list[Fix],
    installed: list[Package],
    candidates: dict[str, str],
    holds: set[str],
    pending: dict[str, list[str]],
    kernel: Kernel,
    urgencies: Urgencies,
    today: datetime.date,
) -> list[Row]:
    """Every fix that concerns this host, with its state, urgency and age, worst first."""
    by_source: dict[str, list[Package]] = {}
    for p in installed:
        by_source.setdefault(p["source"], []).append(p)
    rows: list[Row] = []
    for f in fixes:
        res = fix_state(f, by_source.get(f["source"], []), candidates, holds, pending, kernel)
        if res is None:
            continue
        state, reason = res
        rows.append(
            {
                "state": state,
                "reason": reason,
                "dsa": f["dsa"],
                "date": f["date"],
                "age_days": (today - datetime.date.fromisoformat(f["date"])).days,
                "source": f["source"],
                "fixed_version": f["fixed_version"],
                "cves": f["cves"],
                "urgency": fix_urgency(urgencies, f["source"], f["cves"]),
            }
        )
    rows.sort(key=lambda r: (STATES.index(r["state"]), r["date"], r["dsa"]))
    return rows


def stale_docker(running: list[DockerContainer], current: dict[str, str]) -> list[StaleDocker]:
    """The running containers whose image reference now points to another image."""
    return [
        {**c, "current_id": current[c["image"]]}
        for c in running
        if c["image"] in current and current[c["image"]] != c["image_id"]
    ]


def stale_incus(instances: list[IncusInstance], images: list[IncusImage]) -> list[StaleIncus]:
    """The instances whose image has a newer local sibling (same os, release, arch and variant)."""
    out: list[StaleIncus] = []
    for i in instances:
        same = (i["os"], i["release"], i["arch"], i["variant"])
        newer = [m for m in images if (m["os"], m["release"], m["arch"], m["variant"]) == same and m["serial"] > i["serial"]]
        if newer:
            out.append({**i, "newer": max(newer, key=lambda m: m["serial"])["fingerprint"]})
    return out


def counts(rows: list[Row]) -> dict[State, int]:
    return {s: sum(1 for r in rows if r["state"] == s) for s in STATES}


def signature(rows: list[Row]) -> str:
    """A short fingerprint of the fixes not yet active, so a caller can tell a changed report from a
    repeat."""
    body = "\n".join("%s %s %s" % (r["state"], r["dsa"], r["source"]) for r in rows if r["state"] != "active")
    return hashlib.sha256(body.encode()).hexdigest()[:12]
