from __future__ import annotations

import json
import os

import pytest

from pyezvizapi.token_store import (
    TOKEN_FILE_MODE,
    load_token_file,
    save_token_file,
)


def test_save_token_file_is_atomic_and_owner_only(tmp_path) -> None:
    token_path = tmp_path / "ezviz_token.json"
    token_path.write_text('{"session_id": "stale"}', encoding="utf-8")
    os.chmod(token_path, 0o644)

    token = {"session_id": "current", "rf_session_id": "refresh"}
    save_token_file(token_path, token)

    assert load_token_file(token_path) == token
    assert token_path.stat().st_mode & 0o777 == TOKEN_FILE_MODE
    assert list(tmp_path.glob(f".{token_path.name}.*.tmp")) == []


def test_save_token_file_syncs_parent_directory(monkeypatch, tmp_path) -> None:
    synced: list[object] = []
    monkeypatch.setattr(
        "pyezvizapi.token_store._fsync_directory",
        synced.append,
    )

    save_token_file(tmp_path / "ezviz_token.json", {"session_id": "current"})

    assert synced == [tmp_path]


def test_load_token_file_rejects_non_object_json(tmp_path) -> None:
    token_path = tmp_path / "ezviz_token.json"
    token_path.write_text(json.dumps(["not", "a", "token"]), encoding="utf-8")

    with pytest.raises(ValueError, match="JSON object"):
        load_token_file(token_path)


def test_save_token_file_cleans_temporary_file_after_replace_error(
    monkeypatch,
    tmp_path,
) -> None:
    token_path = tmp_path / "ezviz_token.json"

    def fail_replace(_source, _destination) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr("pyezvizapi.token_store.os.replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        save_token_file(token_path, {"session_id": "secret"})

    assert list(tmp_path.glob(f".{token_path.name}.*.tmp")) == []
