"""Files the readback writes: only into directories that are the running user's and nobody else's,
through a fresh temporary file renamed into place, under a lock so that two runs never collide."""

import contextlib
import errno
import fcntl
import os
import stat
import tempfile
from collections.abc import Callable, Iterator
from typing import BinaryIO

from debian_security_readback.model import ReadbackError


class UnsafeDirError(ReadbackError):
    """A directory someone else could write into: the readback refuses to write there."""


class LockBusyError(ReadbackError):
    """Another run holds the lock: its reports are left alone."""


def safe_dir(path: str) -> None:
    """Create `path` (mode 0755) if it is missing, then refuse it unless it is a real directory owned
    by the running user and not writable by group or others."""
    os.makedirs(path, mode=0o755, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeDirError("%s is not a directory (a symlink is refused)" % path)
    if st.st_uid != os.geteuid():
        raise UnsafeDirError("%s belongs to uid %d, not to the running user (uid %d)" % (path, st.st_uid, os.geteuid()))
    if st.st_mode & 0o022:
        raise UnsafeDirError("%s is writable by group or others (mode %o)" % (path, stat.S_IMODE(st.st_mode)))


def write_atomic_from(
    path: str, mode: int, writer: Callable[[BinaryIO], None], check: Callable[[str], None] | None = None
) -> None:
    """Write `path` through a new temporary file in its directory (never a predictable name, never
    through a symlink), with `mode`, then rename it into place. `check`, given the temporary path,
    may refuse it by raising; the old file then stays as it was."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix="." + os.path.basename(path) + ".")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            writer(f)
        if check is not None:
            check(tmp)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def write_text(path: str, mode: int, text: str) -> None:
    data = text.encode("utf-8")

    def writer(f: BinaryIO) -> None:
        f.write(data)

    write_atomic_from(path, mode, writer)


@contextlib.contextmanager
def exclusive_lock(path: str) -> Iterator[None]:
    """Hold an exclusive lock on `path` for the block, or fail at once when another run holds it."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise LockBusyError("another readback is running (it holds %s)" % path) from e
            raise
        yield
    finally:
        os.close(fd)
