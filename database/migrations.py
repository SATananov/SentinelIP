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