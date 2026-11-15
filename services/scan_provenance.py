from datetime import datetime, timezone
import ipaddress
import uuid

from database.db import DB_PATH, get_connection, initialize_database


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def start_tcp_service_run(scope_id, target_ip, device_id=None, db_path=DB_PATH):
    initialize_database(db_path)
    run_id = str(uuid.uuid4())
    started_at = _timestamp()
    with get_connection(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        scope = connection.execute(
            """SELECT s.scope_type, s.canonical_target, s.authorized, s.enabled,
                      l.network_id
               FROM authorized_scopes s
               LEFT JOIN network_scope_links l ON l.scope_id=s.id WHERE s.id=?""",
            (scope_id,),
        ).fetchone()
        if scope is None or scope[2] != 1 or scope[3] != 1:
            raise ValueError("An enabled authorized scope is required for scan provenance.")
        address = ipaddress.ip_address(target_ip)
        if address.version != 4:
            raise ValueError("Scan provenance target must be IPv4.")
        if scope[0] == "PUBLIC_IPV4":
            target_allowed = target_ip == scope[1]
        elif scope[0] in {"PRIVATE_NETWORK", "PUBLIC_CIDR"}:
            target_allowed = address in ipaddress.ip_network(scope[1], strict=False)
        else:
            target_allowed = connection.execute(
                """SELECT 1 FROM scope_hostname_addresses
                   WHERE scope_id=? AND ipv4_address=? AND approved=1""",
                (scope_id, target_ip),
            ).fetchone() is not None
        if not target_allowed:
            raise ValueError("Scan provenance target is outside the authorized scope.")
        if device_id is not None:
            device = connection.execute(
                "SELECT network_id, scope_id, last_ip_address FROM devices WHERE id=?",
                (device_id,),
            ).fetchone()
            if (device is None or device[2] != target_ip
                    or (scope[0] == "PRIVATE_NETWORK" and device[0] != scope[4])
                    or (scope[0] != "PRIVATE_NETWORK" and device[1] != scope_id)):
                raise ValueError("Scan provenance device does not belong to the authorized scope.")
        connection.execute(
            """INSERT INTO recon_scan_runs
               (id, scope_id, profile, scanner, started_at, status)
               VALUES (?, ?, 'conservative_tcp_services', 'nmap', ?, 'RUNNING')""",
            (run_id, scope_id, started_at),
        )
        connection.execute(
            """INSERT INTO recon_scan_targets
               (run_id, target_ip, device_id, started_at, outcome)
               VALUES (?, ?, ?, ?, 'RUNNING')""",
            (run_id, target_ip, device_id, started_at),
        )
    return run_id


def complete_tcp_service_run(run_id, target_ip, scanner_version=None, db_path=DB_PATH):
    completed_at = _timestamp()
    with get_connection(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """UPDATE recon_scan_targets SET outcome='COMPLETED', completed_at=?
               WHERE run_id=? AND target_ip=? AND outcome='RUNNING'""",
            (completed_at, run_id, target_ip),
        )
        connection.execute(
            """UPDATE recon_scan_runs SET status='COMPLETED', completed_at=?, scanner_version=?
               WHERE id=? AND status='RUNNING'""",
            (completed_at, scanner_version, run_id),
        )


def fail_tcp_service_run(run_id, target_ip, error_category, db_path=DB_PATH):
    completed_at = _timestamp()
    allowed = {"timeout", "capacity", "execution", "parse", "persistence", "cancelled"}
    category = error_category if error_category in allowed else "execution"
    with get_connection(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """UPDATE recon_scan_targets SET outcome=?, completed_at=?, error_category=?
               WHERE run_id=? AND target_ip=? AND outcome='RUNNING'""",
            ("INTERRUPTED" if category == "cancelled" else "FAILED", completed_at, category, run_id, target_ip),
        )
        connection.execute(
            """UPDATE recon_scan_runs SET status=?, completed_at=?, error_category=?
               WHERE id=? AND status='RUNNING'""",
            ("INTERRUPTED" if category == "cancelled" else "FAILED", completed_at, category, run_id),
        )
