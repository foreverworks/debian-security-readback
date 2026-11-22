"""The shapes the readback passes around. Plain dictionaries, typed, so the report is plain JSON."""

from typing import Literal, TypedDict

type State = Literal["blocked", "installed_pending_activation", "available", "active"]

# Worst first: the order of the report's tables and of its rows.
STATES: tuple[State, ...] = ("blocked", "installed_pending_activation", "available", "active")


class ReadbackError(Exception):
    """The readback cannot say anything true (bad source data, a missing tool). It fails; it never
    reports clean."""


class Fix(TypedDict):
    """One DSA's fix for one release."""

    dsa: str
    date: str  # ISO date
    source: str  # the source package
    fixed_version: str
    cves: list[str]


class Package(TypedDict):
    """One installed binary package."""

    name: str
    version: str
    source: str
    source_version: str


class Kernel(TypedDict):
    installed: str | None  # the newest installed linux-image-* version
    running: str | None  # the version of the linux-image-* package of the running kernel
    release: str  # `uname -r`


class Process(TypedDict):
    pid: str
    comm: str
    paths: list[str]  # files it maps or runs that no longer exist on disk


class Row(TypedDict):
    """One fix in the report."""

    state: State
    reason: str
    dsa: str
    date: str
    age_days: int
    source: str
    fixed_version: str
    cves: list[str]
    urgency: str


class DockerContainer(TypedDict):
    name: str
    image: str  # the image reference it was started from
    image_id: str  # the image it runs


class StaleDocker(DockerContainer):
    current_id: str  # the image its reference points to now


class IncusImage(TypedDict):
    fingerprint: str
    os: str
    release: str
    arch: str
    variant: str
    serial: str


class IncusInstance(IncusImage):
    name: str
    project: str


class StaleIncus(IncusInstance):
    newer: str  # the fingerprint of the newest local image of the same os, release, arch and variant


type Urgencies = dict[str, dict[str, str | None]]  # {source: {cve: urgency for the release}}
