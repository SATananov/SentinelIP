"""Minimal SQL seeds for migration tests that intentionally use old schemas."""


def insert_site(connection, name):
    stamp = "2026-10-13T00:00:00+00:00"
    cursor = connection.execute(
        "INSERT INTO sites (name,description,enabled,created_at,updated_at) VALUES (?, '', 1, ?, ?)",
        (name, stamp, stamp),
    )
    return {"id": cursor.lastrowid, "name": name, "enabled": True}


def insert_scope(connection, *, scope_type, target, name="Historical fixture", stamp="2026-10-13T00:00:00"):
    cursor = connection.execute(
        """INSERT INTO authorized_scopes (
            scope_type,canonical_target,name,description,authorized,enabled,
            authorization_confirmed_at,authorization_confirmation_version,
            authorization_source,created_at,updated_at
        ) VALUES (?,?,?,'historical migration fixture',1,1,?,?,?, ?, ?)""",
        (scope_type, target, name, stamp, "historical-fixture-v1", "test_fixture", stamp, stamp),
    )
    return {"id": cursor.lastrowid, "scope_type": scope_type, "canonical_target": target,
            "name": name, "authorized": True, "enabled": True}
