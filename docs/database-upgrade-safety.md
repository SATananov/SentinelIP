# Database upgrade safety

Back up an existing SentinelIP database before upgrading or running destructive
legacy-event retention. The application database is `database/sentinelip.db`.
Use SQLite's online backup API so the backup is a consistent database image.
On POSIX, backups contain the same confidential operational data as the live
database: use a destination directory owned by the operator with mode `0700`
where practical, and create each backup file as mode `0600` before SQLite opens
it. The example below refuses to overwrite an existing backup and verifies the
result before retaining it:

```bash
python - <<'PY'
import os
import sqlite3
import stat
from pathlib import Path

from database.db import get_connection

source = get_connection("database/sentinelip.db")
backup_path = Path("/secure/backups/sentinelip-before-cleanup.sqlite3")
fd = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
try:
    if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
        raise RuntimeError("Backup file is not mode 0600")
finally:
    os.close(fd)
backup = sqlite3.connect(backup_path)
try:
    source.backup(backup)
    result = backup.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise RuntimeError("Backup integrity check failed")
    version = backup.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    print("Backup verified; schema version:", version)
finally:
    backup.close()
    source.close()
PY
```

Replace the example destination with a protected path outside the application
database directory. Do not place it in a shared-writable directory. Keep the
backup until its restore has been tested and the retained history has been
reviewed. File modes protect against ordinary access by other local accounts;
they do not encrypt the backup or protect it from root/Administrator.

To restore, stop the API and all event/database writers first. Preserve the
current database separately using the same secure backup procedure. Restore
through SQLite's backup API rather than copying a live `.db` file with `cp`;
the online backup contains logical database content and does not require
copying live `-journal`, `-wal`, or `-shm` sidecars. Use the production
connection factory for the destination so it validates ownership and tightens
the live database to mode `0600` before SQLite opens it:

```bash
python - <<'PY'
import os
import sqlite3
import stat
from database.db import get_connection

backup_path = "/secure/backups/sentinelip-before-cleanup.sqlite3"
backup_stat = os.lstat(backup_path)
if (not stat.S_ISREG(backup_stat.st_mode)
        or backup_stat.st_uid != os.geteuid()
        or stat.S_IMODE(backup_stat.st_mode) != 0o600):
    raise RuntimeError("Backup must be a regular file with mode 0600")
backup = sqlite3.connect(backup_path)
try:
    destination = get_connection("database/sentinelip.db")
    try:
        backup.backup(destination)
        print("Integrity:", destination.execute("PRAGMA integrity_check").fetchone()[0])
        print("Schema version:", destination.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0])
        print("Foreign-key violations:", destination.execute(
            "PRAGMA foreign_key_check"
        ).fetchall())
    finally:
        destination.close()
finally:
    backup.close()
PY
```

Restore replaces the whole database with its backup-time state. Writes made
after that backup will not be present in the restored database. Test the
procedure against a separate destination before relying on it for recovery.

Migrations run automatically during database initialization. Migration 27
preserves existing device and finding records but internally rebuilds those
tables to add scope relationships; the table copy and replacement are
transactional, and new foreign-key violations are checked before commit.

After upgrading, verify the migration version and foreign-key integrity with
SQLite:

```sql
SELECT MAX(version) FROM schema_migrations;
PRAGMA foreign_key_check;
```

The current schema version is 46. `PRAGMA foreign_key_check` should return no
rows. Keep the backup until the upgraded application and inventory have been
reviewed.
