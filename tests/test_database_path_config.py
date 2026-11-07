import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

import database.db as db


def test_source_tree_default_is_unchanged_when_unconfigured(monkeypatch):
    monkeypatch.delenv(db.DATABASE_PATH_ENV, raising=False)
    assert db.resolve_database_path() == Path(db.__file__).resolve().parent / "sentinelip.db"


@pytest.mark.parametrize("value", [
    "", "   ", "relative.sqlite", "../ambiguous.sqlite", ":memory:",
    "file:target.sqlite", " file:target.sqlite", " /tmp/leading.sqlite",
    "/tmp/trailing.sqlite ", "/tmp/../ambiguous.sqlite", "/tmp/a\x00b.sqlite",
])
def test_invalid_explicit_value_fails_closed(value):
    with pytest.raises(db.DatabaseSecurityError):
        db.resolve_database_path(value)


def test_process_import_uses_explicit_path(tmp_path):
    selected = tmp_path / "configured.sqlite"
    code = "import database.db as d; from pathlib import Path; assert d.DB_PATH == Path(__import__('os').environ['SENTINELIP_DATABASE_PATH'])"
    env = os.environ.copy()
    env.pop("SENTINELIP_LAB_ROOT", None)
    env[db.DATABASE_PATH_ENV] = str(selected)
    subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1], env=env, check=True)


def test_invalid_import_configuration_never_uses_default(tmp_path):
    env = os.environ.copy()
    env[db.DATABASE_PATH_ENV] = "relative.sqlite"
    result = subprocess.run([sys.executable, "-c", "import database.db"], cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "DatabaseSecurityError" in result.stderr


def test_existing_trusted_symlinked_parent_remains_compatible(tmp_path):
    real = tmp_path / "trusted"
    real.mkdir(mode=0o700)
    alias = tmp_path / "trusted-alias"
    alias.symlink_to(real, target_is_directory=True)
    path = alias / "selected.sqlite"
    connection = db.get_connection(path)
    connection.close()
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_final_database_symlink_is_rejected(tmp_path):
    real = tmp_path / "real.sqlite"
    real.touch(mode=0o600)
    alias = tmp_path / "alias.sqlite"
    alias.symlink_to(real)
    with pytest.raises(db.DatabaseSecurityError, match="symbolic links"):
        db.get_connection(alias)


def test_windows_file_backed_core_remains_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "_PLATFORM_NAME", "nt")
    with pytest.raises(db.DatabaseSecurityError, match="ACL hardening is not implemented"):
        db.get_connection(tmp_path / "windows.sqlite")
