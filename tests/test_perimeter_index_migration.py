import sqlite3

from database import migrations as migration_module
from database.db import get_connection, initialize_database


INDEX_COLUMNS = {
    "idx_perimeter_detections_primary_event": ("perimeter_detections", "primary_event_id"),
    "idx_perimeter_policy_correlations_primary_event": (
        "perimeter_policy_correlations",
        "primary_event_id",
    ),
}


def _perimeter_index_columns(connection, table):
    return {
        row[1]: tuple(
            item[2]
            for item in connection.execute(f"PRAGMA index_info('{row[1]}')")
        )
        for row in connection.execute(f"PRAGMA index_list('{table}')")
    }


def _insert_event(connection, site_id):
    return connection.execute(
        """INSERT INTO perimeter_events (
            external_event_id,site_id,sensor_id,source_type,source_key,event_type,
            direction,action,protocol,source_ip,destination_ip,destination_port,
            observed_at,received_at
        ) VALUES ('migration-fixture',?,NULL,'FIREWALL','edge-fw','CONNECTION_ATTEMPT',
            'INBOUND','BLOCK','TCP','203.0.113.20','192.0.2.10',22,
            '2026-10-13T00:00:00+00:00','2026-10-13T00:00:01+00:00')""",
        (site_id,),
    ).lastrowid


def test_schema_45_upgrade_adds_only_expected_indexes_and_preserves_rows(tmp_path, monkeypatch):
    path = tmp_path / "perimeter-index-upgrade.db"
    all_migrations = migration_module.MIGRATIONS
    monkeypatch.setattr(migration_module, "MIGRATIONS", all_migrations[:45])
    initialize_database(path)

    with get_connection(path) as connection:
        site_id = connection.execute(
            "INSERT INTO sites (name,description,enabled,created_at,updated_at) "
            "VALUES ('Migration site','',1,'2026-10-13','2026-10-13')"
        ).lastrowid
        event_id = _insert_event(connection, site_id)
        connection.execute(
            """INSERT INTO perimeter_detections (
                stable_key,detection_type,state,confidence,site_id,primary_event_id,
                event_ids_json,source_ip,destination_ip,destination_port,protocol,
                action,event_count,unique_source_count,first_seen,last_seen,rule_id,
                rule_version,reason,created_at
            ) VALUES ('det-fixture','INBOUND_ATTEMPT','REVIEW','HIGH',?,?,'[]',
                '203.0.113.20','192.0.2.10',22,'TCP','BLOCK',1,1,?,?, 'fixture','1','test',?)""",
            (site_id, event_id, '2026-10-13', '2026-10-13', '2026-10-13'),
        )
        connection.execute(
            """INSERT INTO perimeter_policy_correlations (
                stable_key,correlation_type,state,confidence,site_id,primary_event_id,
                event_ids_json,allowed_event_ids_json,blocked_event_ids_json,source_type,
                source_key,source_ip,destination_ip,destination_port,protocol,primary_action,
                event_count,allow_count,blocked_count,first_seen,last_seen,rule_id,
                rule_version,reason,created_at
            ) VALUES ('policy-fixture','BLOCK_THEN_ALLOW','REVIEW','HIGH',?,?,'[]','[]','[]',
                'FIREWALL','edge-fw','203.0.113.20','192.0.2.10',22,'TCP','BLOCK',2,1,1,
                '2026-10-13','2026-10-13','fixture','1','test','2026-10-13')""",
            (site_id, event_id),
        )
        before_rows = {
            table: connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            for table in (
                "perimeter_events",
                "perimeter_detections",
                "perimeter_policy_correlations",
            )
        }
        before_fk = {
            table: connection.execute(f"PRAGMA foreign_key_list('{table}')").fetchall()
            for table, _ in INDEX_COLUMNS.values()
        }
        for table, column in INDEX_COLUMNS.values():
            indexes = _perimeter_index_columns(connection, table)
            assert not any(columns and columns[0] == column for columns in indexes.values())

    monkeypatch.setattr(migration_module, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)

    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        after_rows = {
            table: connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            for table in before_rows
        }
        assert after_rows == before_rows
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        for index_name, (table, column) in INDEX_COLUMNS.items():
            assert _perimeter_index_columns(connection, table)[index_name] == (column,)
            plan = " ".join(
                str(item[3])
                for item in connection.execute(
                    f"EXPLAIN QUERY PLAN SELECT id FROM {table} WHERE {column}=?", (event_id,)
                )
            )
            assert index_name in plan
        after_fk = {
            table: connection.execute(f"PRAGMA foreign_key_list('{table}')").fetchall()
            for table, _ in INDEX_COLUMNS.values()
        }
        assert after_fk == before_fk


def test_fresh_database_reaches_schema_46_with_both_perimeter_indexes(tmp_path):
    path = tmp_path / "perimeter-index-fresh.db"
    initialize_database(path)
    initialize_database(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 46
        for index_name, (table, column) in INDEX_COLUMNS.items():
            assert _perimeter_index_columns(connection, table)[index_name] == (column,)
            assert connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?",
                (index_name,),
            ).fetchone()[0] == 1
