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
    (
        21,
        (
            "ALTER TABLE web_observations ADD COLUMN browser_session_id TEXT",
            "ALTER TABLE web_observations ADD COLUMN tab_id TEXT",
            """CREATE INDEX idx_web_observations_context_time
               ON web_observations(sensor_id, browser_session_id, tab_id, julianday(observed_at), id)""",
        ),
    ),
    (
        22,
        (
            """CREATE TABLE web_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                detection_type TEXT NOT NULL CHECK (detection_type IN (
                    'CROSS_DOMAIN_LOGIN_REDIRECT', 'LOGIN_DOMAIN_REVIEW',
                    'REDIRECT_CHAIN_REVIEW', 'SUSPICIOUS_DOWNLOAD_FLOW')),
                severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM')),
                confidence TEXT NOT NULL CHECK (confidence = 'MEDIUM'),
                state TEXT NOT NULL CHECK (state = 'REVIEW'),
                sensor_id INTEGER NOT NULL REFERENCES telemetry_sensors(id),
                device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
                primary_observation_id INTEGER REFERENCES web_observations(id) ON DELETE SET NULL,
                hostname TEXT NOT NULL,
                reason TEXT NOT NULL,
                structured_evidence TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE web_detection_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER NOT NULL REFERENCES web_detections(id),
                observation_id INTEGER REFERENCES web_observations(id) ON DELETE SET NULL,
                UNIQUE (detection_id, observation_id)
            )""",
            """CREATE INDEX idx_web_detections_sensor_time
               ON web_detections(sensor_id, last_seen)""",
            """CREATE INDEX idx_web_detections_device_time
               ON web_detections(device_id, last_seen)""",
            """CREATE INDEX idx_web_detection_observations_observation
               ON web_detection_observations(observation_id)""",
        ),
    ),
    (
        23,
        (
            """CREATE TABLE threat_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                threat_type TEXT NOT NULL CHECK (threat_type IN (
                    'SSH_BRUTE_FORCE_THREAT', 'SUSPICIOUS_AUTH_ACTIVITY', 'WEB_CREDENTIAL_FLOW_THREAT')),
                state TEXT NOT NULL CHECK (state IN ('ANOMALOUS', 'SUSPECTED')),
                severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
                confidence TEXT NOT NULL CHECK (confidence IN ('LOW', 'MEDIUM', 'HIGH')),
                device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
                source_ip TEXT,
                sensor_id INTEGER REFERENCES telemetry_sensors(id) ON DELETE SET NULL,
                hostname TEXT,
                primary_evidence_type TEXT NOT NULL CHECK (primary_evidence_type IN ('SSH_EVENT', 'WEB_DETECTION')),
                primary_evidence_id INTEGER NOT NULL,
                anchor_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE threat_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER NOT NULL REFERENCES threat_detections(id),
                evidence_type TEXT NOT NULL CHECK (evidence_type IN ('SSH_EVENT', 'WEB_DETECTION')),
                evidence_id INTEGER NOT NULL,
                ssh_event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
                web_detection_id INTEGER REFERENCES web_detections(id) ON DELETE SET NULL,
                evidence_snapshot TEXT NOT NULL,
                CHECK ((evidence_type = 'SSH_EVENT' AND web_detection_id IS NULL)
                    OR (evidence_type = 'WEB_DETECTION' AND ssh_event_id IS NULL)),
                UNIQUE (threat_id, evidence_type, evidence_id)
            )""",
            """CREATE INDEX idx_threat_detections_source_time ON threat_detections(source_ip, last_seen)""",
            """CREATE INDEX idx_threat_detections_sensor_time ON threat_detections(sensor_id, last_seen)""",
            """CREATE INDEX idx_threat_evidence_ssh ON threat_evidence(ssh_event_id)""",
            """CREATE INDEX idx_threat_evidence_web ON threat_evidence(web_detection_id)""",
            """CREATE INDEX idx_events_threat_window ON events(source_ip, event_type, julianday(timestamp), id)""",
            """CREATE INDEX idx_web_detections_threat_anchor
               ON web_detections(sensor_id, device_id, primary_observation_id, detection_type)""",
        ),
    ),
    (
        24,
        (
            """CREATE TABLE correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                correlation_type TEXT NOT NULL CHECK (correlation_type IN (
                    'SSH_AUTH_ACTIVITY_PATTERN', 'WEB_CREDENTIAL_ACTIVITY_CHAIN')),
                state TEXT NOT NULL CHECK (state IN ('RELATED', 'PATTERN', 'CHAIN_REVIEW')),
                severity TEXT NOT NULL CHECK (severity = 'MEDIUM'),
                confidence TEXT NOT NULL CHECK (confidence IN ('MEDIUM', 'HIGH')),
                device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
                sensor_id INTEGER REFERENCES telemetry_sensors(id) ON DELETE SET NULL,
                source_ip TEXT,
                hostname TEXT,
                primary_entity_type TEXT NOT NULL CHECK (primary_entity_type = 'THREAT'),
                primary_entity_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE correlation_entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id INTEGER NOT NULL REFERENCES correlations(id),
                entity_type TEXT NOT NULL CHECK (entity_type IN ('THREAT', 'WEB_DETECTION')),
                entity_id INTEGER NOT NULL,
                threat_id INTEGER REFERENCES threat_detections(id) ON DELETE SET NULL,
                web_detection_id INTEGER REFERENCES web_detections(id) ON DELETE SET NULL,
                entity_timestamp TEXT NOT NULL,
                snapshot TEXT NOT NULL,
                CHECK ((entity_type = 'THREAT' AND web_detection_id IS NULL)
                    OR (entity_type = 'WEB_DETECTION' AND threat_id IS NULL)),
                CHECK (threat_id IS NULL OR threat_id = entity_id),
                CHECK (web_detection_id IS NULL OR web_detection_id = entity_id),
                UNIQUE (correlation_id, entity_type, entity_id)
            )""",
            """CREATE INDEX idx_correlations_source ON correlations(source_ip, last_seen)""",
            """CREATE INDEX idx_correlations_sensor ON correlations(sensor_id, last_seen)""",
            """CREATE INDEX idx_correlation_entities_threat ON correlation_entities(threat_id)""",
            """CREATE INDEX idx_correlation_entities_web ON correlation_entities(web_detection_id)""",
            """CREATE INDEX idx_threat_evidence_correlation_time
               ON threat_evidence(julianday(json_extract(evidence_snapshot, '$.timestamp')), threat_id, evidence_id)
               WHERE evidence_type = 'SSH_EVENT'""",
        ),
    ),

    (
        25,
        (
            """CREATE TABLE incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                incident_type TEXT NOT NULL CHECK (incident_type IN (
                    'AUTHENTICATION_REVIEW', 'WEB_ACTIVITY_REVIEW', 'MULTI_SIGNAL_REVIEW')),
                status TEXT NOT NULL CHECK (status = 'OPEN'),
                priority TEXT NOT NULL CHECK (priority = 'MEDIUM'),
                primary_correlation_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                reason TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                opened_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE incident_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL REFERENCES incidents(id),
                source_correlation_id INTEGER NOT NULL,
                correlation_id INTEGER REFERENCES correlations(id) ON DELETE SET NULL,
                snapshot TEXT NOT NULL,
                CHECK (correlation_id IS NULL OR correlation_id = source_correlation_id),
                UNIQUE (incident_id, source_correlation_id)
            )""",
            """CREATE INDEX idx_incidents_type_time ON incidents(incident_type, opened_at)""",
            """CREATE INDEX idx_incidents_status_time ON incidents(status, opened_at)""",
            """CREATE INDEX idx_incident_correlations_live ON incident_correlations(correlation_id)""",
        ),
    ),
    (
        26,
        (
            """
            CREATE TABLE IF NOT EXISTS authorized_scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_type TEXT NOT NULL CHECK (
                    scope_type IN (
                        'PRIVATE_NETWORK',
                        'PUBLIC_IPV4',
                        'PUBLIC_CIDR',
                        'HOSTNAME'
                    )
                ),
                canonical_target TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                authorized INTEGER NOT NULL CHECK (authorized IN (0, 1)),
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                authorization_confirmed_at TEXT,
                authorization_confirmation_version TEXT,
                authorization_source TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (scope_type, canonical_target),
                CHECK (
                    authorized = 0
                    OR (
                        authorization_confirmed_at IS NOT NULL
                        AND authorization_confirmation_version IS NOT NULL
                        AND authorization_source IS NOT NULL
                    )
                )
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS network_scope_links (
                network_id INTEGER PRIMARY KEY,
                scope_id INTEGER NOT NULL UNIQUE,
                FOREIGN KEY (network_id) REFERENCES networks(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (scope_id) REFERENCES authorized_scopes(id)
                    ON DELETE CASCADE
            )
            """,
            """
            INSERT OR IGNORE INTO authorized_scopes (
                scope_type,
                canonical_target,
                name,
                description,
                authorized,
                enabled,
                authorization_confirmed_at,
                authorization_confirmation_version,
                authorization_source,
                created_at,
                updated_at
            )
            SELECT
                'PRIVATE_NETWORK',
                cidr,
                name,
                description,
                authorized,
                enabled,
                CASE WHEN authorized = 1 THEN created_at ELSE NULL END,
                CASE WHEN authorized = 1
                    THEN 'legacy_network_authorization_v1' ELSE NULL END,
                CASE WHEN authorized = 1
                    THEN 'legacy_network_record_migration_26' ELSE NULL END,
                created_at,
                updated_at
            FROM networks
            """,
            """
            INSERT OR IGNORE INTO network_scope_links (network_id, scope_id)
            SELECT networks.id, authorized_scopes.id
            FROM networks
            JOIN authorized_scopes
              ON authorized_scopes.scope_type = 'PRIVATE_NETWORK'
             AND authorized_scopes.canonical_target = networks.cidr
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_authorized_scopes_type_enabled
                ON authorized_scopes(scope_type, enabled)
            """,
        ),
    ),
    (
        27,
        (
            """
            CREATE TABLE devices_v27 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                network_id INTEGER,
                scope_id INTEGER,
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
                CHECK (
                    (network_id IS NOT NULL AND scope_id IS NULL)
                    OR (network_id IS NULL AND scope_id IS NOT NULL)
                ),
                FOREIGN KEY (network_id) REFERENCES networks(id),
                FOREIGN KEY (scope_id) REFERENCES authorized_scopes(id)
            )
            """,
            """
            INSERT INTO devices_v27 (
                id, stable_key, network_id, scope_id, mac_address, hostname,
                vendor, first_seen, last_seen, last_ip_address, status,
                identity_confidence, created_at, updated_at
            )
            SELECT id, stable_key, network_id, NULL, mac_address, hostname,
                   vendor, first_seen, last_seen, last_ip_address, status,
                   identity_confidence, created_at, updated_at
            FROM devices
            """,
            "DROP TABLE devices",
            "ALTER TABLE devices_v27 RENAME TO devices",
            "CREATE INDEX idx_devices_network_id ON devices(network_id)",
            "CREATE INDEX idx_devices_scope_id ON devices(scope_id)",
            "CREATE INDEX idx_devices_mac_address ON devices(mac_address)",
            "CREATE INDEX idx_devices_last_ip_address ON devices(last_ip_address)",
            "CREATE INDEX idx_devices_last_seen ON devices(last_seen)",
            """
            CREATE TRIGGER devices_scope_target_insert
            BEFORE INSERT ON devices
            WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM authorized_scopes
                WHERE id = NEW.scope_id
                  AND scope_type = 'PUBLIC_IPV4'
                  AND canonical_target = NEW.last_ip_address
                  AND authorized = 1 AND enabled = 1
                  AND authorization_confirmed_at IS NOT NULL
                  AND authorization_confirmation_version IS NOT NULL
                  AND authorization_source IS NOT NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'scope device target mismatch');
            END
            """,
            """
            CREATE TRIGGER devices_scope_target_update
            BEFORE UPDATE OF scope_id, last_ip_address ON devices
            WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM authorized_scopes
                WHERE id = NEW.scope_id
                  AND scope_type = 'PUBLIC_IPV4'
                  AND canonical_target = NEW.last_ip_address
                  AND authorized = 1 AND enabled = 1
                  AND authorization_confirmed_at IS NOT NULL
                  AND authorization_confirmation_version IS NOT NULL
                  AND authorization_source IS NOT NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'scope device target mismatch');
            END
            """,
            """
            CREATE TABLE scope_device_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('ONLINE', 'OFFLINE')),
                observed_at TEXT NOT NULL,
                source TEXT NOT NULL,
                FOREIGN KEY (scope_id) REFERENCES authorized_scopes(id),
                FOREIGN KEY (device_id) REFERENCES devices(id)
            )
            """,
            """
            CREATE INDEX idx_scope_device_observations_scope_time
                ON scope_device_observations(scope_id, observed_at)
            """,
            """
            CREATE TRIGGER scope_device_observation_owner_insert
            BEFORE INSERT ON scope_device_observations
            WHEN NOT EXISTS (
                SELECT 1 FROM devices
                WHERE id = NEW.device_id AND scope_id = NEW.scope_id
                  AND network_id IS NULL AND last_ip_address = NEW.ip_address
            )
            BEGIN
                SELECT RAISE(ABORT, 'scope observation device mismatch');
            END
            """,
            """
            CREATE TABLE findings_v27 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_type TEXT NOT NULL,
                device_id INTEGER NOT NULL,
                network_id INTEGER,
                scope_id INTEGER,
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
                CHECK (
                    (network_id IS NOT NULL AND scope_id IS NULL)
                    OR (network_id IS NULL AND scope_id IS NOT NULL)
                ),
                FOREIGN KEY (device_id) REFERENCES devices(id),
                FOREIGN KEY (network_id) REFERENCES networks(id),
                FOREIGN KEY (scope_id) REFERENCES authorized_scopes(id),
                FOREIGN KEY (port_id) REFERENCES ports(id),
                FOREIGN KEY (service_id) REFERENCES services(id),
                FOREIGN KEY (change_id) REFERENCES changes(id)
            )
            """,
            """
            INSERT INTO findings_v27 (
                id, finding_type, device_id, network_id, scope_id, port_id,
                service_id, change_id, severity, confidence, status, title,
                reason, recommendation, evidence_type, source, rule_id,
                rule_version, stable_key, first_seen, last_seen, resolved_at,
                metadata_json, created_at, updated_at
            )
            SELECT id, finding_type, device_id, network_id, NULL, port_id,
                   service_id, change_id, severity, confidence, status, title,
                   reason, recommendation, evidence_type, source, rule_id,
                   rule_version, stable_key, first_seen, last_seen, resolved_at,
                   metadata_json, created_at, updated_at
            FROM findings
            """,
            "DROP TABLE findings",
            "ALTER TABLE findings_v27 RENAME TO findings",
            "CREATE INDEX idx_findings_device_status ON findings(device_id, status)",
            "CREATE INDEX idx_findings_network_status ON findings(network_id, status)",
            "CREATE INDEX idx_findings_scope_status ON findings(scope_id, status)",
            "CREATE INDEX idx_findings_type ON findings(finding_type)",
            "CREATE INDEX idx_findings_severity ON findings(severity)",
            "CREATE INDEX idx_findings_status ON findings(status)",
            "CREATE INDEX idx_findings_last_seen ON findings(last_seen)",
            "CREATE INDEX idx_findings_port ON findings(port_id)",
            "CREATE INDEX idx_findings_service ON findings(service_id)",
        ),
    ),
    (
        28,
        (
            "ALTER TABLE authorized_scopes ADD COLUMN resolution_verified_at TEXT",
            "ALTER TABLE authorized_scopes ADD COLUMN resolution_version TEXT",
            "ALTER TABLE authorized_scopes ADD COLUMN resolution_status TEXT",
            "DROP TRIGGER devices_scope_target_insert",
            "DROP TRIGGER devices_scope_target_update",
            """
            CREATE TABLE scope_hostname_addresses (
                scope_id INTEGER NOT NULL,
                ipv4_address TEXT NOT NULL,
                approved INTEGER NOT NULL CHECK (approved IN (0, 1)),
                approved_at TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                resolution_version TEXT NOT NULL,
                PRIMARY KEY (scope_id, ipv4_address),
                FOREIGN KEY (scope_id) REFERENCES authorized_scopes(id)
                    ON DELETE CASCADE
            )
            """,
            "CREATE INDEX idx_scope_hostname_addresses_approved ON scope_hostname_addresses(scope_id, approved, ipv4_address)",
            """
            CREATE TRIGGER scope_hostname_address_insert
            BEFORE INSERT ON scope_hostname_addresses
            WHEN NOT EXISTS (
                SELECT 1 FROM authorized_scopes
                WHERE id = NEW.scope_id AND scope_type = 'HOSTNAME'
                  AND authorized = 1
                  AND authorization_confirmed_at IS NOT NULL
                  AND authorization_confirmation_version IS NOT NULL
                  AND authorization_source IS NOT NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'hostname address requires confirmed hostname scope');
            END
            """,
            """
            CREATE TRIGGER scope_hostname_address_approved_update
            BEFORE UPDATE OF approved ON scope_hostname_addresses
            WHEN NEW.approved = 1 AND NOT EXISTS (
                SELECT 1 FROM authorized_scopes
                WHERE id = NEW.scope_id AND scope_type = 'HOSTNAME'
                  AND authorized = 1
                  AND authorization_confirmed_at IS NOT NULL
                  AND authorization_confirmation_version IS NOT NULL
                  AND authorization_source IS NOT NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'hostname address requires confirmed hostname scope');
            END
            """,
            """
            CREATE TRIGGER devices_scope_target_insert
            BEFORE INSERT ON devices
            WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM authorized_scopes s
                WHERE s.id = NEW.scope_id AND s.authorized = 1 AND s.enabled = 1
                  AND s.authorization_confirmed_at IS NOT NULL
                  AND s.authorization_confirmation_version IS NOT NULL
                  AND s.authorization_source IS NOT NULL
                  AND (
                    (s.scope_type = 'PUBLIC_IPV4' AND s.canonical_target = NEW.last_ip_address)
                    OR (s.scope_type = 'HOSTNAME' AND s.resolution_status = 'CURRENT' AND EXISTS (
                        SELECT 1 FROM scope_hostname_addresses a
                        WHERE a.scope_id = s.id AND a.ipv4_address = NEW.last_ip_address
                          AND a.approved = 1
                    ))
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'scope device target mismatch');
            END
            """,
            """
            CREATE TRIGGER devices_scope_target_update
            BEFORE UPDATE OF scope_id, last_ip_address ON devices
            WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM authorized_scopes s
                WHERE s.id = NEW.scope_id AND s.authorized = 1 AND s.enabled = 1
                  AND s.authorization_confirmed_at IS NOT NULL
                  AND s.authorization_confirmation_version IS NOT NULL
                  AND s.authorization_source IS NOT NULL
                  AND (
                    (s.scope_type = 'PUBLIC_IPV4' AND s.canonical_target = NEW.last_ip_address)
                    OR (s.scope_type = 'HOSTNAME' AND s.resolution_status = 'CURRENT' AND EXISTS (
                        SELECT 1 FROM scope_hostname_addresses a
                        WHERE a.scope_id = s.id AND a.ipv4_address = NEW.last_ip_address
                          AND a.approved = 1
                    ))
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'scope device target mismatch');
            END
            """,
        ),
    ),
    (
        29,
        (
            """CREATE TABLE scope_cidr_addresses (
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id) ON DELETE CASCADE,
                canonical_cidr TEXT NOT NULL,
                ipv4_address TEXT NOT NULL,
                PRIMARY KEY (scope_id, ipv4_address)
            )""",
            """CREATE TRIGGER scope_cidr_address_insert BEFORE INSERT ON scope_cidr_addresses
            WHEN NOT EXISTS (
                SELECT 1 FROM authorized_scopes s WHERE s.id = NEW.scope_id
                AND s.scope_type = 'PUBLIC_CIDR' AND s.canonical_target = NEW.canonical_cidr
            )
            BEGIN SELECT RAISE(ABORT, 'CIDR address requires matching scope'); END""",
            "DROP TRIGGER devices_scope_target_insert",
            "DROP TRIGGER devices_scope_target_update",
            """CREATE TRIGGER devices_scope_target_insert
            BEFORE INSERT ON devices
            WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM authorized_scopes s
                WHERE s.id = NEW.scope_id AND s.authorized = 1 AND s.enabled = 1
                  AND s.authorization_confirmed_at IS NOT NULL
                  AND s.authorization_confirmation_version IS NOT NULL
                  AND s.authorization_source IS NOT NULL
                  AND (
                    (s.scope_type = 'PUBLIC_IPV4' AND s.canonical_target = NEW.last_ip_address)
                    OR (s.scope_type = 'PUBLIC_CIDR' AND EXISTS (
                        SELECT 1 FROM scope_cidr_addresses a
                        WHERE a.scope_id = s.id AND a.canonical_cidr = s.canonical_target
                          AND a.ipv4_address = NEW.last_ip_address
                    ))
                    OR (s.scope_type = 'HOSTNAME' AND s.resolution_status = 'CURRENT' AND EXISTS (
                        SELECT 1 FROM scope_hostname_addresses a
                        WHERE a.scope_id = s.id AND a.ipv4_address = NEW.last_ip_address
                          AND a.approved = 1
                    ))
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'scope device target mismatch');
            END""",
            """CREATE TRIGGER devices_scope_target_update
            BEFORE UPDATE OF scope_id, last_ip_address ON devices
            WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM authorized_scopes s
                WHERE s.id = NEW.scope_id AND s.authorized = 1 AND s.enabled = 1
                  AND s.authorization_confirmed_at IS NOT NULL
                  AND s.authorization_confirmation_version IS NOT NULL
                  AND s.authorization_source IS NOT NULL
                  AND (
                    (s.scope_type = 'PUBLIC_IPV4' AND s.canonical_target = NEW.last_ip_address)
                    OR (s.scope_type = 'PUBLIC_CIDR' AND EXISTS (
                        SELECT 1 FROM scope_cidr_addresses a
                        WHERE a.scope_id = s.id AND a.canonical_cidr = s.canonical_target
                          AND a.ipv4_address = NEW.last_ip_address
                    ))
                    OR (s.scope_type = 'HOSTNAME' AND s.resolution_status = 'CURRENT' AND EXISTS (
                        SELECT 1 FROM scope_hostname_addresses a
                        WHERE a.scope_id = s.id AND a.ipv4_address = NEW.last_ip_address
                          AND a.approved = 1
                    ))
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'scope device target mismatch');
            END""",
        ),
    ),
    (
        30,
        (
            """CREATE TABLE sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE remote_sensors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER NOT NULL REFERENCES sites(id),
                sensor_uuid TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                platform TEXT NOT NULL, version TEXT NOT NULL,
                capabilities TEXT NOT NULL,
                enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
                credential_salt TEXT NOT NULL, credential_hash TEXT NOT NULL,
                credential_iterations INTEGER NOT NULL,
                credential_revoked_at TEXT,
                last_seen_at TEXT, registered_at TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                UNIQUE (id, site_id)
            )""",
            """CREATE TABLE sensor_enrollment_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER NOT NULL REFERENCES sites(id),
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                revoked_at TEXT, consumed_at TEXT,
                sensor_id INTEGER UNIQUE REFERENCES remote_sensors(id)
            )""",
            """CREATE TABLE remote_scope_sites (
                scope_id INTEGER PRIMARY KEY REFERENCES authorized_scopes(id),
                site_id INTEGER NOT NULL REFERENCES sites(id),
                created_at TEXT NOT NULL,
                UNIQUE (scope_id, site_id)
            )""",
            """CREATE TABLE sensor_scope_assignments (
                sensor_id INTEGER NOT NULL,
                scope_id INTEGER NOT NULL,
                site_id INTEGER NOT NULL,
                canonical_target TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (sensor_id, scope_id),
                FOREIGN KEY (sensor_id, site_id) REFERENCES remote_sensors(id, site_id),
                FOREIGN KEY (scope_id, site_id) REFERENCES remote_scope_sites(scope_id, site_id)
            )""",
            "CREATE INDEX remote_sensors_site ON remote_sensors(site_id, id)",
        ),
    ),
    (
        31,
        (
            """CREATE TABLE sensor_transport_nonces (
                sensor_id INTEGER NOT NULL REFERENCES remote_sensors(id) ON DELETE CASCADE,
                nonce TEXT NOT NULL,
                request_timestamp INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (sensor_id, nonce)
            )""",
            "CREATE INDEX sensor_transport_nonces_request_timestamp ON sensor_transport_nonces(request_timestamp)",
            "CREATE INDEX sensor_transport_nonces_sensor_received ON sensor_transport_nonces(sensor_id, received_at)",
        ),
    ),
    (
        32,
        (
            """CREATE TABLE remote_sensor_tasks (
                id TEXT PRIMARY KEY,
                sensor_id INTEGER NOT NULL,
                site_id INTEGER NOT NULL,
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                task_type TEXT NOT NULL CHECK (task_type IN ('DISCOVER_NETWORK','DISCOVER_SERVICES')),
                status TEXT NOT NULL CHECK (status IN ('PENDING','CLAIMED','RUNNING','COMPLETED','FAILED','CANCELLED')),
                target_device_id INTEGER REFERENCES devices(id),
                target_ip TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                claimed_at TEXT,
                started_at TEXT,
                completed_at TEXT,
                failed_at TEXT,
                error_code TEXT,
                error_message TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                created_by_source TEXT NOT NULL,
                result_digest TEXT,
                FOREIGN KEY (sensor_id, site_id) REFERENCES remote_sensors(id, site_id),
                CHECK ((task_type = 'DISCOVER_NETWORK' AND target_device_id IS NULL AND target_ip IS NULL)
                    OR (task_type = 'DISCOVER_SERVICES' AND target_device_id IS NOT NULL AND target_ip IS NOT NULL))
            )""",
            "CREATE INDEX remote_sensor_tasks_claim ON remote_sensor_tasks(sensor_id, status, expires_at, created_at)",
        ),
    ),
)


MIGRATIONS_REQUIRING_FOREIGN_KEYS_DISABLED = frozenset({27})


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

        disable_foreign_keys = version in MIGRATIONS_REQUIRING_FOREIGN_KEYS_DISABLED
        prior_foreign_key_violations = set()
        if disable_foreign_keys:
            prior_foreign_key_violations = set(
                connection.execute("PRAGMA foreign_key_check").fetchall()
            )
            connection.execute("PRAGMA foreign_keys = OFF")
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
            if disable_foreign_keys:
                violations = connection.execute("PRAGMA foreign_key_check").fetchall()
                new_violations = set(violations) - prior_foreign_key_violations
                if new_violations:
                    raise sqlite3.IntegrityError(
                        "Migration would introduce foreign-key violations."
                    )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            if disable_foreign_keys:
                connection.execute("PRAGMA foreign_keys = ON")
