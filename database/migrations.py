import sqlite3


MIGRATIONS = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            authorized INTEGER NOT NULL CHECK (authorized IN (0, 1)),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stable_key TEXT NOT NULL UNIQUE,
            network_id INTEGER NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_ip_address TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('ONLINE', 'OFFLINE')),
            identity_confidence TEXT NOT NULL CHECK (
                identity_confidence IN ('HIGH', 'MEDIUM', 'LOW')
            ),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (network_id) REFERENCES networks(id)
        )
        """,
    ),
    (
        3,
        """
        CREATE TABLE IF NOT EXISTS device_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            status TEXT NOT NULL CHECK (status = 'ONLINE'),
            observed_at TEXT NOT NULL,
            source TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (network_id) REFERENCES networks(id)
        )
        """,
    ),
    (
        4,
        (
            """
            CREATE INDEX IF NOT EXISTS idx_devices_network_id
                ON devices(network_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_devices_mac_address
                ON devices(mac_address)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_devices_last_ip_address
                ON devices(last_ip_address)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_devices_last_seen
                ON devices(last_seen)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_device_observations_device_observed
                ON device_observations(device_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_device_observations_network_ip_observed
                ON device_observations(network_id, ip_address, observed_at)
            """,
        ),
    ),
    (
        5,
        """
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            port_number INTEGER NOT NULL,
            transport TEXT NOT NULL,
            state TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (device_id, port_number, transport),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
        """,
    ),
    (
        6,
        """
        CREATE TABLE IF NOT EXISTS port_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            port_number INTEGER NOT NULL,
            transport TEXT NOT NULL,
            state TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            source TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (port_id) REFERENCES ports(id)
        )
        """,
    ),
    (
        7,
        """
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL UNIQUE,
            service_name TEXT,
            product TEXT,
            version TEXT,
            extra_info TEXT,
            confidence TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (port_id) REFERENCES ports(id)
        )
        """,
    ),
    (
        8,
        """
        CREATE TABLE IF NOT EXISTS service_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER,
            device_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            service_name TEXT,
            product TEXT,
            version TEXT,
            extra_info TEXT,
            confidence TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            source TEXT NOT NULL,
            FOREIGN KEY (service_id) REFERENCES services(id),
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (port_id) REFERENCES ports(id)
        )
        """
    ),
    (
        9,
        (
            """
            CREATE INDEX IF NOT EXISTS idx_ports_device
                ON ports(device_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_ports_lookup
                ON ports(device_id, port_number, transport)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_port_observations_port_observed
                ON port_observations(port_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_services_device
                ON services(device_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_services_port
                ON services(port_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_service_observations_service_observed
                ON service_observations(service_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_service_observations_device_observed
                ON service_observations(device_id, observed_at)
            """,
        ),
    ),
    (
        10,
        """
        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            change_type TEXT NOT NULL,
            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,
            port_id INTEGER,
            service_id INTEGER,
            observed_at TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            previous_value TEXT,
            current_value TEXT,
            evidence_type TEXT NOT NULL,
            message TEXT NOT NULL,
            correlation_key TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (network_id) REFERENCES networks(id),
            FOREIGN KEY (port_id) REFERENCES ports(id),
            FOREIGN KEY (service_id) REFERENCES services(id)
        )
        """,
    ),
    (
        11,
        (
            """
            CREATE INDEX IF NOT EXISTS idx_changes_device_observed
                ON changes(device_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_changes_network_observed
                ON changes(network_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_changes_type_observed
                ON changes(change_type, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_changes_port
                ON changes(port_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_changes_service
                ON changes(service_id)
            """,
        ),
    ),
    (
        12,
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_type TEXT NOT NULL,
            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,
            port_id INTEGER,
            service_id INTEGER,
            change_id INTEGER,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            status TEXT NOT NULL,
            title TEXT NOT NULL,
            reason TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            source TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            stable_key TEXT NOT NULL UNIQUE,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (network_id) REFERENCES networks(id),
            FOREIGN KEY (port_id) REFERENCES ports(id),
            FOREIGN KEY (service_id) REFERENCES services(id),
            FOREIGN KEY (change_id) REFERENCES changes(id)
        )
        """,
    ),
    (
        13,
        (
            """
            CREATE INDEX IF NOT EXISTS idx_findings_device_status
                ON findings(device_id, status)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_findings_network_status
                ON findings(network_id, status)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_findings_type
                ON findings(finding_type)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_findings_severity
                ON findings(severity)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_findings_status
                ON findings(status)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_findings_last_seen
                ON findings(last_seen)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_findings_port
                ON findings(port_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_findings_service
                ON findings(service_id)
            """,
        ),
    ),
    (
        14,
        """
        CREATE TABLE IF NOT EXISTS cve_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            source TEXT NOT NULL,
            source_reference TEXT,
            product TEXT NOT NULL,
            vendor TEXT,
            version_expression TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            published_at TEXT,
            modified_at TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (source, cve_id, product, version_expression)
        )
        """,
    ),
    (
        15,
        """
        CREATE TABLE IF NOT EXISTS cve_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_record_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            port_id INTEGER,
            service_id INTEGER NOT NULL,
            finding_id INTEGER,
            status TEXT NOT NULL,
            confidence TEXT NOT NULL,
            observed_product TEXT,
            observed_version TEXT,
            evidence_source TEXT NOT NULL,
            evidence_observed_at TEXT NOT NULL,
            match_reason TEXT NOT NULL,
            stable_key TEXT NOT NULL UNIQUE,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (cve_record_id) REFERENCES cve_records(id),
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (port_id) REFERENCES ports(id),
            FOREIGN KEY (service_id) REFERENCES services(id),
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        )
        """,
    ),
    (
        16,
        (
            """
            CREATE INDEX IF NOT EXISTS idx_cve_records_product
                ON cve_records(product)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_cve_matches_device
                ON cve_matches(device_id, last_seen)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_cve_matches_service
                ON cve_matches(service_id, last_seen)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_cve_matches_status
                ON cve_matches(status)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_cve_matches_cve_record
                ON cve_matches(cve_record_id)
            """,
        ),
    ),
    (
        17,
        """
        CREATE TABLE IF NOT EXISTS telemetry_sensors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            sensor_type TEXT NOT NULL,
            device_id INTEGER,
            token_salt BLOB NOT NULL,
            token_hash TEXT NOT NULL,
            token_iterations INTEGER NOT NULL,
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            privacy_mode TEXT NOT NULL,
            retention_days INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
        """,
    ),
    (
        18,
        """
        CREATE TABLE IF NOT EXISTS web_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id INTEGER NOT NULL,
            external_event_id TEXT NOT NULL,
            device_id INTEGER,
            observed_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            scheme TEXT,
            hostname TEXT NOT NULL,
            path TEXT,
            referrer_domain TEXT,
            redirect_from_domain TEXT,
            redirect_to_domain TEXT,
            has_login_form INTEGER NOT NULL CHECK (has_login_form IN (0, 1)),
            has_password_form INTEGER NOT NULL CHECK (has_password_form IN (0, 1)),
            download_detected INTEGER NOT NULL CHECK (download_detected IN (0, 1)),
            source TEXT NOT NULL,
            retention_until TEXT NOT NULL,
            metadata_json TEXT,
            UNIQUE (sensor_id, external_event_id),
            FOREIGN KEY (sensor_id) REFERENCES telemetry_sensors(id),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
        """,
    ),
    (
        19,
        """
        CREATE TABLE IF NOT EXISTS dns_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id INTEGER NOT NULL,
            external_event_id TEXT NOT NULL,
            device_id INTEGER,
            observed_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            queried_domain TEXT NOT NULL,
            query_type TEXT NOT NULL,
            response_status TEXT NOT NULL,
            resolved_addresses_json TEXT NOT NULL,
            resolver TEXT,
            ttl INTEGER,
            source TEXT NOT NULL,
            retention_until TEXT NOT NULL,
            metadata_json TEXT,
            UNIQUE (sensor_id, external_event_id),
            FOREIGN KEY (sensor_id) REFERENCES telemetry_sensors(id),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
        """,
    ),
    (
        20,
        (
            """
            CREATE INDEX IF NOT EXISTS idx_telemetry_sensors_key
                ON telemetry_sensors(sensor_key)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_telemetry_sensors_device
                ON telemetry_sensors(device_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_web_observations_sensor_time
                ON web_observations(sensor_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_web_observations_device_time
                ON web_observations(device_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_web_observations_hostname_time
                ON web_observations(hostname, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_dns_observations_sensor_time
                ON dns_observations(sensor_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_dns_observations_device_time
                ON dns_observations(device_id, observed_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_dns_observations_domain_time
                ON dns_observations(queried_domain, observed_at)
            """,
        ),
    ),
)


def apply_migrations(connection: sqlite3.Connection):
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )
    connection.commit()

    for version, statement in MIGRATIONS:
        row = connection.execute(
            "SELECT 1 FROM schema_migrations WHERE version = ?",
            (version,),
        ).fetchone()

        if row is not None:
            continue

        try:
            connection.execute("BEGIN")
            statements = (
                (statement,)
                if isinstance(statement, str)
                else statement
            )

            for migration_statement in statements:
                connection.execute(migration_statement)

            connection.execute(
                """
                INSERT INTO schema_migrations (version, applied_at)
                VALUES (?, datetime('now'))
                """,
                (version,),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise