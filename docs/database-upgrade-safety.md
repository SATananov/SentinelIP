# Database upgrade safety

Back up an existing SentinelIP database before upgrading. Migrations run
automatically during database initialization. Migration 27 preserves existing
device and finding records but internally rebuilds those tables to add scope
relationships; the table copy and replacement are transactional, and new
foreign-key violations are checked before commit.

After upgrading, verify the migration version and foreign-key integrity with
SQLite:

```sql
SELECT MAX(version) FROM schema_migrations;
PRAGMA foreign_key_check;
```

The current schema version is 29. `PRAGMA foreign_key_check` should return no
rows. Keep the backup until the upgraded application and inventory have been
reviewed.
