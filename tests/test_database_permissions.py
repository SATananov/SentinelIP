import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

import database.db as database_db


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX filesystem contract")


def _mode(path):
    return stat.S_IMODE(Path(path).stat().st_mode)


@pytest.mark.parametrize("umask", [0o022, 0o000])
def test_new_database_is_secure_before_sqlite_initialization(tmp_path, umask):
    path = tmp_path / f"fresh-{umask:o}.sqlite3"
    prior_umask = os.umask(umask)
    try:
        database_db.initialize_database(path)
    finally:
        os.umask(prior_umask)

    assert _mode(path) == 0o600
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46


def test_sqlite_never_opens_new_database_before_mode_is_secure(tmp_path, monkeypatch):
    path = tmp_path / "secure-before-open.sqlite3"
    real_connect = sqlite3.connect
    observed_modes = []

    def inspect_then_connect(database_path, *args, **kwargs):
        observed_modes.append(stat.S_IMODE(Path(database_path).stat().st_mode))
        return real_connect(database_path, *args, **kwargs)

    monkeypatch.setattr(database_db.sqlite3, "connect", inspect_then_connect)
    connection = database_db.get_connection(path)
    connection.close()

    assert observed_modes == [0o600]


@pytest.mark.parametrize("old_mode", [0o644, 0o666, 0o640, 0o620, 0o700, 0o711, 0o610])
def test_existing_database_is_tightened_without_replacement_or_data_loss(tmp_path, old_mode):
    path = tmp_path / f"existing-{old_mode:o}.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE retained (value TEXT NOT NULL)")
        connection.execute("INSERT INTO retained VALUES ('preserved')")
    path.chmod(old_mode)
    before = path.stat()

    connection = database_db.get_connection(path)
    try:
        assert connection.execute("SELECT value FROM retained").fetchone() == ("preserved",)
    finally:
        connection.close()

    after = path.stat()
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)


def test_already_secure_database_is_not_chmodded(tmp_path, monkeypatch):
    path = tmp_path / "secure.sqlite3"
    connection = database_db.get_connection(path)
    connection.close()
    path.chmod(0o600)

    def unexpected_chmod(*_args, **_kwargs):
        raise AssertionError("secure database should not be chmodded")

    monkeypatch.setattr(database_db.os, "fchmod", unexpected_chmod)
    connection = database_db.get_connection(path)
    connection.close()
    assert _mode(path) == 0o600


@pytest.mark.parametrize("parent_mode", [0o777, 0o775, 0o730, 0o702])
def test_group_or_world_writable_parent_is_rejected_before_file_creation(tmp_path, parent_mode):
    parent = tmp_path / f"unsafe-{parent_mode:o}"
    parent.mkdir()
    parent.chmod(parent_mode)
    path = parent / "database.sqlite3"

    with pytest.raises(database_db.DatabaseSecurityError, match="group- or world-writable"):
        database_db.get_connection(path)

    assert not path.exists()


@pytest.mark.parametrize("parent_mode", [0o700, 0o755])
def test_safe_parent_modes_are_accepted_and_not_changed(tmp_path, parent_mode):
    parent = tmp_path / f"safe-{parent_mode:o}"
    parent.mkdir()
    parent.chmod(parent_mode)
    path = parent / "database.sqlite3"

    connection = database_db.get_connection(path)
    connection.close()

    assert _mode(path) == 0o600
    assert stat.S_IMODE(parent.stat().st_mode) == parent_mode


def test_missing_or_non_directory_parent_fails_before_sqlite(tmp_path, monkeypatch):
    missing_path = tmp_path / "missing" / "database.sqlite3"
    not_dir = tmp_path / "not-a-directory"
    not_dir.write_text("x")
    nested_path = not_dir / "database.sqlite3"
    sqlite_calls = []
    monkeypatch.setattr(database_db.sqlite3, "connect", lambda *args, **kwargs: sqlite_calls.append(args))

    with pytest.raises(database_db.DatabaseSecurityError, match="parent directory is unavailable"):
        database_db.get_connection(missing_path)
    with pytest.raises(database_db.DatabaseSecurityError, match="parent path is not a directory"):
        database_db.get_connection(nested_path)

    assert sqlite_calls == []


def test_parent_owned_by_another_account_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "other-owner" / "database.sqlite3"
    parent_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=os.geteuid() + 1)
    sqlite_calls = []
    monkeypatch.setattr(database_db.os, "stat", lambda _path: parent_stat)
    monkeypatch.setattr(database_db.sqlite3, "connect", lambda *args, **kwargs: sqlite_calls.append(args))

    with pytest.raises(database_db.DatabaseSecurityError, match="parent directory is not owned"):
        database_db.get_connection(path)

    assert sqlite_calls == []


def test_symlink_database_path_is_rejected_without_changing_target(tmp_path, monkeypatch):
    real_connect = sqlite3.connect
    target = tmp_path / "real.sqlite3"
    with real_connect(target) as connection:
        connection.execute("CREATE TABLE retained (value TEXT)")
        connection.execute("INSERT INTO retained VALUES ('safe')")
    target.chmod(0o644)
    before = target.stat()
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    sqlite_calls = []
    monkeypatch.setattr(database_db.sqlite3, "connect", lambda *args, **kwargs: sqlite_calls.append(args))

    with pytest.raises(database_db.DatabaseSecurityError, match="symbolic links are not permitted"):
        database_db.get_connection(link)

    after = target.stat()
    assert stat.S_IMODE(after.st_mode) == 0o644
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert sqlite_calls == []
    with real_connect(target) as connection:
        assert connection.execute("SELECT value FROM retained").fetchone() == ("safe",)


@pytest.mark.parametrize("path_kind", ["directory", "fifo"])
def test_non_regular_database_paths_are_rejected_without_blocking(tmp_path, path_kind):
    path = tmp_path / f"{path_kind}.sqlite3"
    if path_kind == "directory":
        path.mkdir()
    elif not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    else:
        os.mkfifo(path)

    with pytest.raises(database_db.DatabaseSecurityError, match="regular file"):
        database_db.get_connection(path)


def test_wrong_database_owner_fails_before_chmod_or_sqlite(tmp_path, monkeypatch):
    path = tmp_path / "wrong-owner.sqlite3"
    with sqlite3.connect(path):
        pass
    path.chmod(0o644)
    chmod_calls = []
    sqlite_calls = []
    monkeypatch.setattr(database_db.os, "geteuid", lambda: path.stat().st_uid + 1)
    monkeypatch.setattr(database_db.os, "fchmod", lambda *args: chmod_calls.append(args))
    monkeypatch.setattr(database_db.sqlite3, "connect", lambda *args, **kwargs: sqlite_calls.append(args))

    with pytest.raises(database_db.DatabaseSecurityError, match="not owned by the Core account"):
        database_db.get_connection(path)

    assert chmod_calls == []
    assert sqlite_calls == []
    assert _mode(path) == 0o644


def test_fchmod_failure_fails_closed_before_sqlite(tmp_path, monkeypatch):
    path = tmp_path / "chmod-failure.sqlite3"
    with sqlite3.connect(path):
        pass
    path.chmod(0o644)
    sqlite_calls = []

    def fail_fchmod(*_args):
        raise PermissionError("denied")

    monkeypatch.setattr(database_db.os, "fchmod", fail_fchmod)
    monkeypatch.setattr(database_db.sqlite3, "connect", lambda *args, **kwargs: sqlite_calls.append(args))

    with pytest.raises(database_db.DatabaseSecurityError, match="permissions could not be tightened") as exc:
        database_db.get_connection(path)

    assert str(path) in str(exc.value)
    assert "mode 0600" in str(exc.value)
    assert sqlite_calls == []
    assert _mode(path) == 0o644


def test_secure_creation_failure_fails_closed_before_sqlite(tmp_path, monkeypatch):
    path = tmp_path / "creation-failure.sqlite3"
    sqlite_calls = []

    def fail_open(*_args, **_kwargs):
        raise PermissionError("read-only filesystem")

    monkeypatch.setattr(database_db.os, "open", fail_open)
    monkeypatch.setattr(database_db.sqlite3, "connect", lambda *args, **kwargs: sqlite_calls.append(args))

    with pytest.raises(database_db.DatabaseSecurityError, match="secure creation failed") as exc:
        database_db.get_connection(path)

    assert str(path) in str(exc.value)
    assert sqlite_calls == []
    assert not path.exists()


def test_memory_database_bypasses_filesystem_security(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database_db,
        "_secure_posix_database",
        lambda _path: (_ for _ in ()).throw(AssertionError("filesystem path check called")),
    )
    connection = database_db.get_connection(":memory:")
    try:
        assert connection.execute("SELECT 1").fetchone() == (1,)
    finally:
        connection.close()


def test_relative_database_path_remains_relative_to_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    connection = database_db.get_connection("relative.sqlite3")
    connection.close()

    assert (tmp_path / "relative.sqlite3").exists()
    assert _mode(tmp_path / "relative.sqlite3") == 0o600


def test_concurrent_secure_creation_never_replaces_or_exposes_database(tmp_path):
    path = tmp_path / "concurrent.sqlite3"

    def open_and_close(_):
        connection = database_db.get_connection(path)
        connection.execute("CREATE TABLE IF NOT EXISTS retained (value TEXT)")
        connection.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(open_and_close, range(8)))

    assert _mode(path) == 0o600
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='retained'"
        ).fetchone() == ("retained",)


def test_windows_file_database_fails_closed_without_acl_support(tmp_path, monkeypatch):
    path = tmp_path / "windows.sqlite3"
    sqlite_calls = []
    monkeypatch.setattr(database_db, "_PLATFORM_NAME", "nt")
    monkeypatch.setattr(database_db.sqlite3, "connect", lambda *args, **kwargs: sqlite_calls.append(args))

    with pytest.raises(database_db.DatabaseSecurityError, match="Windows ACL hardening is not implemented"):
        database_db.get_connection(path)

    assert sqlite_calls == []
    assert not path.exists()


def test_database_directory_mode_is_not_modified(tmp_path):
    parent_mode = stat.S_IMODE(tmp_path.stat().st_mode)
    connection = database_db.get_connection(tmp_path / "database.sqlite3")
    connection.close()
    assert stat.S_IMODE(tmp_path.stat().st_mode) == parent_mode


def test_rollback_journal_wal_and_shm_are_not_more_permissive_than_database(tmp_path):
    path = tmp_path / "sidecars.sqlite3"
    connection = database_db.get_connection(path)
    try:
        connection.execute("CREATE TABLE records (value TEXT)")
        connection.commit()
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO records VALUES ('rollback')")
        journal = Path(f"{path}-journal")
        assert journal.exists()
        assert stat.S_IMODE(journal.stat().st_mode) == 0o600
        connection.commit()
        assert not journal.exists()

        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO records VALUES ('wal')")
        wal = Path(f"{path}-wal")
        shm = Path(f"{path}-shm")
        assert wal.exists() and shm.exists()
        assert stat.S_IMODE(wal.stat().st_mode) <= 0o600
        assert stat.S_IMODE(shm.stat().st_mode) <= 0o600
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        connection.commit()
    finally:
        connection.close()
