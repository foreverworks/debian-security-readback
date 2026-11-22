"""The configuration: a TOML file, then command-line flags on top. Every key is optional."""

import dataclasses
import tomllib
from collections.abc import Mapping

from debian_security_readback.facts import DEFAULT_CONTAINER_MARKERS
from debian_security_readback.model import STATES, State

DEFAULT_PATH = "/etc/debian-security-readback.toml"
DSA_LIST_URL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list"
TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"


class ConfigError(Exception):
    """The configuration cannot be used as written."""


@dataclasses.dataclass(frozen=True)
class Config:
    host: str = ""  # empty: the kernel's node name
    release: str = ""  # empty: VERSION_CODENAME from /etc/os-release
    cache_dir: str = "/var/cache/debian-security-readback"
    out_dir: str = "/var/lib/debian-security-readback"
    dsa_list_url: str = DSA_LIST_URL
    tracker_url: str = TRACKER_URL
    cache_max_age_hours: int = 20
    download_deadline_seconds: int = 300
    recent_days: int = 30
    container_cgroup_markers: tuple[str, ...] = DEFAULT_CONTAINER_MARKERS
    docker: bool = True
    incus: bool = True
    fail_on: tuple[State, ...] = ()


_FIELDS = {f.name: f for f in dataclasses.fields(Config)}


def _str(data: Mapping[str, object], key: str, default: str) -> str:
    v = data.get(key, default)
    if not isinstance(v, str):
        raise ConfigError("%s must be a string" % key)
    return v


def _int(data: Mapping[str, object], key: str, default: int) -> int:
    v = data.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ConfigError("%s must be a whole number, 0 or more" % key)
    return v


def _bool(data: Mapping[str, object], key: str, default: bool) -> bool:
    v = data.get(key, default)
    if not isinstance(v, bool):
        raise ConfigError("%s must be true or false" % key)
    return v


def _strs(data: Mapping[str, object], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    v = data.get(key, default)
    if isinstance(v, tuple):
        v = list(v)
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ConfigError("%s must be a list of non-empty strings" % key)
    return tuple(str(x) for x in v)


def _states(data: Mapping[str, object], key: str, default: tuple[State, ...]) -> tuple[State, ...]:
    out: list[State] = []
    for v in _strs(data, key, default):
        state = next((s for s in STATES if s == v), None)
        if state is None:
            raise ConfigError("%s: unknown state %s (states: %s)" % (key, v, ", ".join(STATES)))
        out.append(state)
    return tuple(out)


def from_mapping(data: Mapping[str, object], base: Config | None = None) -> Config:
    """A Config from `data` (a parsed TOML file, or flags), on top of `base`."""
    unknown = sorted(set(data) - set(_FIELDS))
    if unknown:
        raise ConfigError("unknown key%s: %s" % ("s" if len(unknown) > 1 else "", ", ".join(unknown)))
    b = base or Config()
    return Config(
        host=_str(data, "host", b.host),
        release=_str(data, "release", b.release),
        cache_dir=_str(data, "cache_dir", b.cache_dir),
        out_dir=_str(data, "out_dir", b.out_dir),
        dsa_list_url=_str(data, "dsa_list_url", b.dsa_list_url),
        tracker_url=_str(data, "tracker_url", b.tracker_url),
        cache_max_age_hours=_int(data, "cache_max_age_hours", b.cache_max_age_hours),
        download_deadline_seconds=_int(data, "download_deadline_seconds", b.download_deadline_seconds),
        recent_days=_int(data, "recent_days", b.recent_days),
        container_cgroup_markers=_strs(data, "container_cgroup_markers", b.container_cgroup_markers),
        docker=_bool(data, "docker", b.docker),
        incus=_bool(data, "incus", b.incus),
        fail_on=_states(data, "fail_on", b.fail_on),
    )


def parse(text: str, base: Config | None = None) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError("not TOML: %s" % e) from e
    return from_mapping(data, base)


def load(path: str | None) -> Config:
    """The file at `path`, or DEFAULT_PATH when there is one, or the defaults. A path given and not
    there is an error."""
    try:
        with open(path or DEFAULT_PATH, encoding="utf-8") as f:
            return parse(f.read())
    except FileNotFoundError:
        if path:
            raise ConfigError("%s: no such file" % path) from None
        return Config()
    except OSError as e:
        raise ConfigError("%s: %s" % (path or DEFAULT_PATH, e)) from e
