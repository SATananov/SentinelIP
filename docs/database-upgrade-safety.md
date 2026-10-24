# Database upgrade safety

Back up an existing SentinelIP database before upgrading or running destructive
legacy-event retention. The application database is `database/sentinelip.db`.
Use SQLite's online backup API so the backup is a consistent database image:

```bash
python - <<'PY'
import sqlite3

source = sqlite3.connect("database/sentinelip.db")
backup = sqlite3.connect("/secure/backups/sentinelip-before-cleanup.sqlite3")
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
database directory. Keep the backup until its restore has been tested and the
retained history has been reviewed.

To restore, stop the API and all event/database writers first. Preserve the
current database separately, then copy the backup image into the live database
using the same SQLite backup API:

```bash
python - <<'PY'
import sqlite3

backup = sqlite3.connect("/secure/backups/sentinelip-before-cleanup.sqlite3")
destination = sqlite3.connect("database/sentinelip.db")
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

The current schema version is 45. `PRAGMA foreign_key_check` should return no
rows. Keep the backup until the upgraded application and inventory have been
reviewed.
