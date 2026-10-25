# Phase 36C: Core Database Filesystem Permissions

## Risk and result

Phase 35 found that SQLite could create the default Core database,
`database/sentinelip.db`, with mode `0644` under a normal `022` umask. Another
nonprivileged local account could therefore read operational events, inventory,
scopes, Incident Review records, task history, and sensor credential hashes.
Sensor credentials stored in the database are hashes, not plaintext; the other
operational records are still confidential.

Phase 36 closes that local filesystem confidentiality risk for supported
POSIX file-backed Core databases. Production connections pass through
`database.db.get_connection()`, which secures and validates the path before
calling SQLite. New files are created exclusively at mode `0600`; existing
permissive files are tightened to exactly `0600` before SQLite opens them.
Symlinks, non-regular files, wrong ownership, and unsafe parents fail closed.
The database is not encrypted at rest.

## Permission contract

On POSIX, a file-backed database must be in an existing directory that is a
directory, owned by the effective Core user, and not group- or world-writable.
The directory is not created or chmodded automatically. An owned `0755`
directory is accepted; `0700` is preferred for a dedicated data directory. Do
not put the database in a shared-writable directory. A service account must own
the database and its parent directory. Shared-group database access is not the
default contract.

New database files use exclusive secure pre-creation at `0600` before SQLite
opens them. Existing paths must be regular files owned by the effective Core
user; final-component symlinks are rejected. Existing files are normalized to
exactly `0600` without replacing their inode or database contents. The parent
is checked but not modified. Relative and absolute caller-supplied paths use
the same checks. `:memory:` databases do not use filesystem permission checks.
If any check or mode change fails, the file-backed connection is refused.

## SQLite sidecars and temporary data

Disposable Linux checks using the production connection factory observed the
rollback journal as a regular file owned by the Core user at mode `0600`; it
was removed after commit. With WAL enabled only in disposable verification
databases, the `-wal` and `-shm` files were also Core-owned and no broader than
`0600`. These results held under umasks `022` and `000`. SQLite created these
sidecars in the protected database directory; this documents observed SQLite
behavior on Linux and is not a claim for every platform or filesystem.

`database/perimeter_lifecycle.py` explicitly uses `PRAGMA temp_store = FILE`
for temporary tables. A disposable SQLite temporary-database exercise observed
the unlinked `/tmp/etilqs_*` file at mode `0600` under both tested umasks. This
is an environment observation, not a cross-platform guarantee or a new temp
file policy. The lifecycle operation uses SQLite temporary tables; temporary
files are not retained as application history.

## Backup and restore

Backups contain the same confidential logical database content as the live
database. On POSIX, create them as mode `0600` in an operator-controlled
directory, preferably mode `0700`. `docs/database-upgrade-safety.md` provides
a SQLite online-backup example that securely pre-creates the destination with
exclusive creation and verifies integrity and schema version. Do not overwrite
an existing backup implicitly. The disposable backup/restore test passed
integrity and schema-version checks at version 46.

For live backup, use SQLite's online backup API; do not copy the active `.db`
file with `cp` or copy its `-journal`, `-wal`, or `-shm` sidecars. For restore,
stop Core and all database writers, preserve the current database separately,
and restore through SQLite's backup API into the production connection factory
or a securely prepared replacement. Verify `PRAGMA integrity_check`, schema
version, and `PRAGMA foreign_key_check` before resuming service. Startup through
the factory tightens a restored `0644` database to `0600` before SQLite opens
it. Backup destination confidentiality and retention remain operator
responsibilities; permissions are not backup encryption.

## Platform and deployment support

File-backed Core databases are currently supported by this permission
implementation on POSIX. Windows Core file-backed database connections
intentionally fail closed because the Core database has no verified Windows
ACL implementation. The repository's Windows ACL code protects sensor
credentials and grants under a sensor-specific policy; it is not reused as a
Core database ACL implementation. Windows sensor support is separate and is
documented in `docs/remote-sensor-10g.md`. No real Windows Core ACL verification
is claimed.

The repository documents local Core startup and sensor-enabled Core deployment,
but has no Windows Core installer or Windows Core service deployment workflow.
Container deployment is not documented. If an operator uses a bind mount that
does not permit ownership/mode validation or tightening, file-backed Core
startup will fail closed. Network filesystem behavior is not claimed.

The default database parent is the existing repository `database/` directory;
it is accepted when owned by the Core account and not group/world writable.
The application does not change its mode. Other nonprivileged local OS users
are outside the intended access boundary and must not be granted database read
access. Root/Administrator, a compromised Core account, physical access, or
access to a disk image can bypass ordinary file permissions. Mode `0600` is
not encryption at rest.

## Verification and scope

Phase 36B permission tests cover secure creation under umasks `022` and `000`,
existing-file tightening, owner and parent validation, symlink and non-regular
rejection, fail-closed behavior, in-memory operation, concurrency, and Linux
sidecars. Phase 36C adds umask sidecar checks and a disposable online backup and
restore integrity/schema test. Focused migration, Phase 32 atomic persistence,
and Phase 34 source/top-IP regressions are also run during close-out.

No schema change was required; the schema remains version 46. The actual local
`database/sentinelip.db` is not modified by these tests.

This phase does not close other known risks: database permissions do not
encrypt data; privileged administrators can bypass them; backup protection is
operator-managed; Windows Core file-backed support remains unavailable pending
verified ACL support; sensor pending results remain memory-only; inventory
observation retention remains undefined; historical device lists remain
unbounded; Nmap output is still checked after capture; and `/events` exact
counts and deep `OFFSET` pagination remain separate scaling concerns.

No evidence from this phase requires reopening Phases 23, 24, 25, 26, 27, 28,
30, 32, or 34.
