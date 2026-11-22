"""What the Debian security tracker says: its DSA list (date, source package, fixed version, CVEs) and
its JSON (urgency per CVE and release). Pure: text in, data out."""

import datetime
import json
import re
from collections.abc import Iterator
from typing import TextIO

from debian_security_readback.debversion import is_version
from debian_security_readback.model import Fix, ReadbackError, Urgencies

URGENCY_RANK = {
    "unimportant": 0,
    "end-of-life": 0,
    "not yet assigned": 0,
    "low": 1,
    "low*": 1,
    "medium": 2,
    "medium*": 2,
    "high": 3,
    "high**": 3,
}

# The least a real DSA list and a real tracker JSON hold. A challenge page or an error served with a
# 200 must fail the readback, never read as "no fixes".
MIN_DSA_ENTRIES = 100
MIN_TRACKER_PACKAGES = 1000
# The largest one package's entry may be. The biggest, `linux`, was 37 MB in November 2026.
MAX_TRACKER_VALUE = 128 << 20

_HEAD = re.compile(r"^\[(\d+ \w+ \d{4})\] (DSA-\d+-\d+) (\S+) - ")
_RELEASE_LINE = re.compile(r"^\s+\[(\w+)\] - (\S+) (\S+)")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def _date(text: str) -> str:
    day, month, year = text.split()
    if month not in _MONTHS:
        raise ReadbackError("the DSA list has a date it cannot read: %s" % text)
    return datetime.date(int(year), _MONTHS[month], int(day)).isoformat()


def parse_dsa_list(text: str, release: str) -> list[Fix]:
    """The DSAs with a fixed version for `release`, in the list's order (newest first)."""
    fixes: list[Fix] = []
    head: Fix | None = None
    for line in text.splitlines():
        m = _HEAD.match(line)
        if m:
            head = {"dsa": m.group(2), "date": _date(m.group(1)), "source": m.group(3), "fixed_version": "", "cves": []}
            continue
        if head is None:
            continue
        if line.strip().startswith("{"):
            head["cves"].extend(re.findall(r"CVE-\d+-\d+", line))
        m = _RELEASE_LINE.match(line)
        # A marker such as <end-of-life> or <not-affected> in place of a version is not a fix.
        if m and m.group(1) == release and is_version(m.group(3)):
            fixes.append({**head, "source": m.group(2), "fixed_version": m.group(3), "cves": head["cves"]})
    return fixes


def validate_dsa_text(text: str, release: str, min_entries: int = MIN_DSA_ENTRIES) -> list[Fix]:
    """The DSA list must look like the list: at least `min_entries` DSAs and one with a fix for
    `release`. Returns the parsed fixes."""
    heads = len(re.findall(r"^\[\d+ \w+ \d{4}\] DSA-\d+-\d+ ", text, re.M))
    if heads < min_entries:
        raise ReadbackError("the DSA list is not the DSA list (%d entries)" % heads)
    fixes = parse_dsa_list(text, release)
    if not fixes:
        raise ReadbackError(
            "the DSA list has no fixes for %s: DSAs are published for Debian stable releases only, "
            "not for testing or unstable (set `release` if the codename is wrong)" % release
        )
    return fixes


def iter_tracker(f: TextIO, chunk: int = 1 << 22, max_value: int = MAX_TRACKER_VALUE) -> Iterator[tuple[str, object]]:
    """Stream the tracker's top-level object as (package, value) pairs, so the whole file (about
    90 MB) is never held in memory at once. A single value longer than max_value characters fails."""
    dec = json.JSONDecoder()
    buf = f.read(chunk)
    pos = 0
    eof = not buf

    def fill() -> None:
        nonlocal buf, pos, eof
        data = f.read(chunk)
        if not data:
            eof = True
            return
        buf = buf[pos:] + data
        pos = 0

    def skip(chars: str) -> None:
        nonlocal pos
        while True:
            while pos < len(buf) and buf[pos] in chars:
                pos += 1
            if pos < len(buf) or eof:
                return
            fill()

    def decode() -> object:
        nonlocal pos
        while True:
            try:
                value: object
                value, end = dec.raw_decode(buf, pos)
                pos = end
                return value
            except json.JSONDecodeError:
                if eof:
                    raise
                if len(buf) - pos > max_value:
                    raise ReadbackError("the tracker JSON has a value longer than %d characters" % max_value) from None
                fill()

    skip(" \t\r\n")
    if pos >= len(buf) or buf[pos] != "{":
        raise ReadbackError("the tracker JSON is not the tracker JSON (not an object)")
    pos += 1
    while True:
        skip(" \t\r\n,")
        if pos >= len(buf):
            raise ReadbackError("the tracker JSON ends early")
        if buf[pos] == "}":
            return
        key = decode()
        if not isinstance(key, str):
            raise ReadbackError("the tracker JSON is not the tracker JSON (a key is not a string)")
        skip(" \t\r\n:")
        yield key, decode()


def load_urgencies(f: TextIO, sources: set[str], release: str, min_packages: int = MIN_TRACKER_PACKAGES) -> Urgencies:
    """{source: {cve: urgency for `release`}} for the wanted sources, streamed. Fails unless the file
    has the tracker's shape (many packages, each a mapping of CVE ids)."""
    out: Urgencies = {}
    seen = 0
    try:
        for pkg, entries in iter_tracker(f):
            if not isinstance(entries, dict):
                raise ReadbackError("the tracker JSON is not the tracker JSON (%s is not a mapping)" % pkg)
            seen += 1
            if pkg in sources:
                out[pkg] = {str(cve): _urgency(d, release) for cve, d in entries.items() if isinstance(d, dict)}
    except ValueError as e:
        raise ReadbackError("the tracker JSON does not parse: %s" % e) from e
    if seen < min_packages:
        raise ReadbackError("the tracker JSON is not the tracker JSON (%d packages)" % seen)
    return out


def _urgency(entry: dict[object, object], release: str) -> str | None:
    releases = entry.get("releases")
    rel = releases.get(release) if isinstance(releases, dict) else None
    u = rel.get("urgency") if isinstance(rel, dict) else None
    return u if isinstance(u, str) else None


def fix_urgency(urgencies: Urgencies, source: str, cves: list[str]) -> str:
    """The highest urgency the tracker gives any of the fix's CVEs ('unknown' if none)."""
    best, name = -1, "unknown"
    entries = urgencies.get(source, {})
    for cve in cves:
        u = entries.get(cve)
        if u is not None and URGENCY_RANK.get(u, 0) > best:
            best, name = URGENCY_RANK.get(u, 0), u
    return name
