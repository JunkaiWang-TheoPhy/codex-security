"""Stage and publish POSIX scan-local files through verified directory descriptors."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def stage_file(
    parent_fd: int, filename: str, payload: bytes, owner_read_write: bool
) -> Iterator[int]:
    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            if owner_read_write:
                os.fchmod(descriptor, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(descriptor)
        yield descriptor
    finally:
        try:
            entry = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
            if os.path.samestat(os.fstat(descriptor), entry):
                os.unlink(filename, dir_fd=parent_fd)
        except FileNotFoundError:
            # Successful publication has already removed the temporary name.
            pass
        finally:
            os.close(descriptor)


def _rename_exclusive(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        rename = getattr(libc, "renameat2", None)
        flag = 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        flag = 4  # RENAME_EXCL
    else:
        rename = None
    code = errno.ENOSYS
    if rename is not None:
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), flag) == 0:
            return
        code = ctypes.get_errno()
    detail = os.strerror(code)
    if code in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL}:
        detail = f"cannot publish a new file atomically without hard links or exclusive rename ({detail})"
    raise OSError(code, detail, destination)


def publish_new_file(parent_fd: int, source: str, destination: str) -> None:
    try:
        os.link(
            source, destination, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False
        )
    except OSError as exc:
        if exc.errno not in {
            errno.EPERM,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
            errno.ENOSYS,
            errno.EXDEV,
            errno.EMLINK,
        }:
            raise
        _rename_exclusive(parent_fd, source, destination)
    else:
        os.unlink(source, dir_fd=parent_fd)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
