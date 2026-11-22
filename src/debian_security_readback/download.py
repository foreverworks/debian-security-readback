"""Downloads of the tracker's files: https (or file) only, a hard deadline, a size cap, and a cached
copy that a bad download never replaces."""

import http.client
import os
import socket
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import BinaryIO, Protocol

from debian_security_readback import __version__
from debian_security_readback.files import write_atomic_from
from debian_security_readback.model import ReadbackError

SCHEMES = ("https", "file")
READ_SIZE = 1 << 16
SOCKET_TIMEOUT_S = 60.0  # the longest wait for any one read, never past the deadline
MAX_REDIRECTS = 5


class _Body(Protocol):
    def read1(self, n: int = ..., /) -> bytes: ...


def redirect_allowed(old: str, new: str, schemes: tuple[str, ...]) -> bool:
    """A redirect may go to an allowed scheme, and never from https to anything else."""
    old_scheme = urllib.parse.urlsplit(old).scheme
    new_scheme = urllib.parse.urlsplit(new).scheme
    return new_scheme in schemes and new_scheme != "file" and (old_scheme != "https" or new_scheme == "https")


def _left(deadline_at: float) -> float:
    left = deadline_at - time.monotonic()
    if left <= 0:
        raise ReadbackError("the download did not finish within its deadline")
    return left


def _connect(u: urllib.parse.SplitResult, deadline_at: float) -> http.client.HTTPConnection:
    timeout = min(SOCKET_TIMEOUT_S, _left(deadline_at))
    host, port = u.hostname or "", u.port
    proxy = None if urllib.request.proxy_bypass(host) else urllib.request.getproxies().get(u.scheme)
    if u.scheme == "https":
        if proxy:
            p = urllib.parse.urlsplit(proxy if "//" in proxy else "http://" + proxy)
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(p.hostname or "", p.port or 80, timeout=timeout)
            conn.set_tunnel(host, port or 443)
            return conn
        return http.client.HTTPSConnection(host, port, timeout=timeout)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _http_body(
    url: str, deadline_at: float, schemes: tuple[str, ...], max_bytes: int
) -> tuple[_Body, socket.socket, list[Callable[[], None]]]:
    for _ in range(MAX_REDIRECTS + 1):
        u = urllib.parse.urlsplit(url)
        conn = _connect(u, deadline_at)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        try:
            conn.request(
                "GET", path, headers={"User-Agent": "debian-security-readback/" + __version__, "Accept-Encoding": "identity"}
            )
            sock = conn.sock
            if not isinstance(sock, socket.socket):
                raise ReadbackError("no connection to %s" % u.netloc)
            sock.settimeout(min(SOCKET_TIMEOUT_S, _left(deadline_at)))
            resp = conn.getresponse()
        except BaseException:
            conn.close()
            raise
        if resp.status in (301, 302, 303, 307, 308):
            new = urllib.parse.urljoin(url, resp.getheader("Location") or "")
            resp.close()
            conn.close()
            if not redirect_allowed(url, new, schemes):
                raise ReadbackError("refused a redirect from %s to %s" % (url, new))
            url = new
            continue
        if resp.status != 200:
            resp.close()
            conn.close()
            raise ReadbackError("HTTP %d %s" % (resp.status, resp.reason))
        length = resp.getheader("Content-Length")
        if length and length.isdigit() and int(length) > max_bytes:
            resp.close()
            conn.close()
            raise ReadbackError("%s bytes is more than the %d allowed" % (length, max_bytes))
        return resp, sock, [resp.close, conn.close]
    raise ReadbackError("more than %d redirects" % MAX_REDIRECTS)


def _copy(body: _Body, out: BinaryIO, deadline_at: float, max_bytes: int, sock: socket.socket | None) -> None:
    total = 0
    while True:
        left = _left(deadline_at)
        if sock is not None and sock.fileno() != -1:  # -1 once the response has read its whole body
            sock.settimeout(min(SOCKET_TIMEOUT_S, left))
        chunk = body.read1(READ_SIZE)
        if not chunk:
            return
        total += len(chunk)
        if total > max_bytes:
            raise ReadbackError("more than the %d bytes allowed" % max_bytes)
        out.write(chunk)


def download(url: str, out: BinaryIO, deadline_s: float, max_bytes: int, schemes: tuple[str, ...] = SCHEMES) -> None:
    """Write what `url` serves to `out`, or raise ReadbackError (or OSError). Nothing waits past the
    deadline: every read is bounded by the time left."""
    deadline_at = time.monotonic() + deadline_s
    u = urllib.parse.urlsplit(url)
    if u.scheme not in schemes:
        raise ReadbackError("%s: only %s URLs are allowed" % (url, " and ".join(schemes)))
    if u.scheme == "file":
        with open(urllib.request.url2pathname(u.path), "rb") as f:
            _copy(f, out, deadline_at, max_bytes, None)
        return
    try:
        body, sock, closers = _http_body(url, deadline_at, schemes, max_bytes)
        try:
            _copy(body, out, deadline_at, max_bytes, sock)
        finally:
            for close in closers:
                close()
    except TimeoutError as e:
        raise ReadbackError("the download did not finish within its deadline (%s)" % e) from e
    except http.client.HTTPException as e:
        raise ReadbackError("HTTP: %s" % (type(e).__name__)) from e


def fetch(
    url: str,
    dest: str,
    check: Callable[[str], None],
    max_age_s: float,
    deadline_s: float,
    max_bytes: int,
    schemes: tuple[str, ...] = SCHEMES,
) -> tuple[str, str]:
    """`url` downloaded to `dest`, unless `dest` is younger than max_age_s. A download that fails,
    runs past deadline_s, is larger than max_bytes or does not pass `check` (a callable on the
    downloaded file that raises ReadbackError) never replaces the cached copy: a stale cached copy is
    used instead. Returns (path, note), where the note says so, or is empty."""
    if os.path.exists(dest) and time.time() - os.path.getmtime(dest) < max_age_s:
        return dest, ""
    try:
        write_atomic_from(dest, 0o644, lambda f: download(url, f, deadline_s, max_bytes, schemes), check)
        return dest, ""
    except (OSError, ReadbackError, ValueError) as e:
        if not os.path.exists(dest):
            raise ReadbackError("%s: %s, and no cached copy" % (url, e)) from e
        age = int((time.time() - os.path.getmtime(dest)) / 3600)
        where = urllib.parse.urlsplit(url).netloc or url
        return dest, "%s could not be refreshed (%s): using a copy %d h old" % (where, e, age)
