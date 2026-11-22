"""Debian version ordering (deb-version(5)), so deciding needs no dpkg."""

import functools
import re

_VERSION = re.compile(r"^(?:\d+:)?[0-9][A-Za-z0-9.+~:-]*$")


def is_version(text: str) -> bool:
    """True for a Debian version; false for the tracker's markers such as `<end-of-life>`."""
    return bool(_VERSION.match(text))


def _order(ch: str) -> int:
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _take(s: str, digits: bool) -> tuple[str, str]:
    i = 0
    while i < len(s) and s[i].isdigit() == digits:
        i += 1
    return s[:i], s[i:]


def _cmp_part(a: str, b: str) -> int:
    while a or b:
        da, a = _take(a, digits=False)
        db, b = _take(b, digits=False)
        for i in range(max(len(da), len(db))):
            oa = _order(da[i] if i < len(da) else "")
            ob = _order(db[i] if i < len(db) else "")
            if oa != ob:
                return -1 if oa < ob else 1
        na, a = _take(a, digits=True)
        nb, b = _take(b, digits=True)
        ia, ib = int(na or 0), int(nb or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def split_version(v: str) -> tuple[int, str, str]:
    """(epoch, upstream, revision)."""
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), upstream, revision


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1 as Debian orders a against b."""
    ea, ua, ra = split_version(a)
    eb, ub, rb = split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_part(ua, ub) or _cmp_part(ra, rb)


version_key = functools.cmp_to_key(compare_versions)
