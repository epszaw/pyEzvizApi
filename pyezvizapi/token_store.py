"""Secure JSON persistence helpers for EZVIZ session tokens."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, cast

TOKEN_FILE_MODE = 0o600


def _fsync_directory(path: Path) -> None:
    """Best-effort fsync for directory metadata on supported platforms."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        # Some platforms/filesystems allow opening directories but not syncing them.
        pass
    finally:
        os.close(directory_fd)


def load_token_file(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and validate a token dictionary from a JSON file."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Token file must contain a JSON object")
    return cast(dict[str, Any], payload)


def save_token_file(
    path: str | os.PathLike[str],
    token: dict[str, Any],
) -> None:
    """Atomically persist a token with owner-only file permissions.

    The caller owns directory creation and permissions. The temporary file is
    created beside the destination so ``os.replace`` remains atomic.
    """

    destination = Path(path)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.chmod(temporary_path, TOKEN_FILE_MODE)
            json.dump(token, temporary, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        os.chmod(destination, TOKEN_FILE_MODE)
        _fsync_directory(destination.parent)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
