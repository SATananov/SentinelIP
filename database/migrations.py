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
    (
        33,
        (
            """CREATE TABLE perimeter_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_event_id TEXT NOT NULL,
                site_id INTEGER NOT NULL,
                sensor_id INTEGER,
                source_type TEXT NOT NULL CHECK (source_type IN ('FIREWALL','ROUTER','GATEWAY','SENSOR','OTHER')),
                source_key TEXT NOT NULL,
                event_type TEXT NOT NULL CHECK (event_type IN ('CONNECTION_ATTEMPT','FLOW','POLICY_DECISION','OTHER')),
                direction TEXT NOT NULL CHECK (direction IN ('INBOUND','OUTBOUND','LATERAL','UNKNOWN')),
                action TEXT NOT NULL CHECK (action IN ('ALLOW','BLOCK','REJECT','UNKNOWN')),
                protocol TEXT NOT NULL CHECK (protocol IN ('TCP','UDP','ICMP','OTHER')),
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port INTEGER CHECK (source_port IS NULL OR source_port BETWEEN 1 AND 65535),
                destination_port INTEGER CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535),
                interface TEXT,
                source_reference TEXT,
                raw_event_hash TEXT,
                metadata_json TEXT,
                observed_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                UNIQUE (site_id, source_key, external_event_id),
                FOREIGN KEY (site_id) REFERENCES sites(id),
                FOREIGN KEY (sensor_id, site_id) REFERENCES remote_sensors(id, site_id),
                CHECK (protocol NOT IN ('TCP','UDP') OR destination_port IS NOT NULL),
                CHECK (protocol != 'ICMP' OR (source_port IS NULL AND destination_port IS NULL))
            )""",
            "CREATE INDEX idx_perimeter_site_observed ON perimeter_events(site_id, observed_at)",
            "CREATE INDEX idx_perimeter_source_observed ON perimeter_events(source_ip, observed_at)",
            "CREATE INDEX idx_perimeter_destination_observed ON perimeter_events(destination_ip, destination_port, observed_at)",
            "CREATE INDEX idx_perimeter_action_direction ON perimeter_events(action, direction, observed_at)",
        ),
    ),
    (
        34,
        (
            """CREATE TABLE perimeter_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                detection_type TEXT NOT NULL CHECK (detection_type IN ('INBOUND_ATTEMPT','REPEATED_INBOUND_ATTEMPTS')),
                state TEXT NOT NULL CHECK (state = 'REVIEW'),
                confidence TEXT NOT NULL CHECK (confidence = 'HIGH'),
                site_id INTEGER NOT NULL REFERENCES sites(id),
                sensor_id INTEGER,
                primary_event_id INTEGER NOT NULL REFERENCES perimeter_events(id),
                event_ids_json TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port INTEGER CHECK (source_port IS NULL OR source_port BETWEEN 1 AND 65535),
                destination_port INTEGER CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535),
                protocol TEXT NOT NULL CHECK (protocol IN ('TCP','UDP','ICMP','OTHER')),
                action TEXT NOT NULL CHECK (action IN ('ALLOW','BLOCK','REJECT','UNKNOWN')),
                event_count INTEGER NOT NULL CHECK (event_count >= 1),
                unique_source_count INTEGER NOT NULL CHECK (unique_source_count >= 1),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sensor_id, site_id) REFERENCES remote_sensors(id, site_id),
                CHECK (protocol NOT IN ('TCP','UDP') OR destination_port IS NOT NULL)
            )""",
            "CREATE INDEX idx_perimeter_detections_site_seen ON perimeter_detections(site_id,last_seen)",
            "CREATE INDEX idx_perimeter_detections_source_seen ON perimeter_detections(source_ip,last_seen)",
            "CREATE INDEX idx_perimeter_detections_destination ON perimeter_detections(destination_ip,destination_port,last_seen)",
            "CREATE INDEX idx_perimeter_detections_type_action ON perimeter_detections(detection_type,action,last_seen)",
        ),
    ),
    (
        35,
        (
            """CREATE TABLE perimeter_policy_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                correlation_type TEXT NOT NULL CHECK (correlation_type IN ('BLOCK_THEN_ALLOW','ALLOW_THEN_BLOCK')),
                state TEXT NOT NULL CHECK (state = 'REVIEW'),
                confidence TEXT NOT NULL CHECK (confidence = 'HIGH'),
                site_id INTEGER NOT NULL REFERENCES sites(id),
                sensor_id INTEGER,
                primary_event_id INTEGER NOT NULL REFERENCES perimeter_events(id),
                event_ids_json TEXT NOT NULL,
                allowed_event_ids_json TEXT NOT NULL,
                blocked_event_ids_json TEXT NOT NULL,
                source_type TEXT NOT NULL CHECK (source_type IN ('FIREWALL','ROUTER','GATEWAY','SENSOR','OTHER')),
                source_key TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535),
                protocol TEXT NOT NULL CHECK (protocol IN ('TCP','UDP','ICMP','OTHER')),
                primary_action TEXT NOT NULL CHECK (primary_action IN ('ALLOW','BLOCK','REJECT')),
                event_count INTEGER NOT NULL CHECK (event_count >= 2),
                allow_count INTEGER NOT NULL CHECK (allow_count >= 1),
                blocked_count INTEGER NOT NULL CHECK (blocked_count >= 1),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sensor_id, site_id) REFERENCES remote_sensors(id, site_id),
                CHECK (protocol NOT IN ('TCP','UDP') OR destination_port IS NOT NULL),
                CHECK (event_count = allow_count + blocked_count)
            )""",
            "CREATE INDEX idx_perimeter_policy_site_seen ON perimeter_policy_correlations(site_id,last_seen)",
            "CREATE INDEX idx_perimeter_policy_source_seen ON perimeter_policy_correlations(source_ip,last_seen)",
            "CREATE INDEX idx_perimeter_policy_destination ON perimeter_policy_correlations(destination_ip,destination_port,last_seen)",
            "CREATE INDEX idx_perimeter_policy_type_seen ON perimeter_policy_correlations(correlation_type,last_seen)",
        ),
    ),
    (
        36,
        (
            """CREATE TABLE perimeter_host_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                correlation_type TEXT NOT NULL CHECK (correlation_type = 'DESTINATION_DEVICE_MATCH'),
                state TEXT NOT NULL CHECK (state = 'REVIEW'),
                confidence TEXT NOT NULL CHECK (confidence = 'HIGH'),
                site_id INTEGER NOT NULL REFERENCES sites(id),
                sensor_id INTEGER,
                event_id INTEGER NOT NULL UNIQUE REFERENCES perimeter_events(id),
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                network_id INTEGER NOT NULL REFERENCES networks(id),
                device_id INTEGER NOT NULL REFERENCES devices(id),
                destination_ip TEXT NOT NULL,
                destination_port INTEGER CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535),
                protocol TEXT NOT NULL CHECK (protocol IN ('TCP','UDP','ICMP','OTHER')),
                action TEXT NOT NULL CHECK (action IN ('ALLOW','BLOCK','REJECT','UNKNOWN')),
                observed_at TEXT NOT NULL,
                device_last_seen TEXT NOT NULL,
                device_status TEXT NOT NULL CHECK (device_status IN ('ONLINE','OFFLINE')),
                identity_confidence TEXT NOT NULL CHECK (identity_confidence IN ('HIGH','MEDIUM','LOW')),
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sensor_id, site_id) REFERENCES remote_sensors(id, site_id),
                CHECK (protocol NOT IN ('TCP','UDP') OR destination_port IS NOT NULL)
            )""",
            "CREATE INDEX idx_perimeter_host_site_seen ON perimeter_host_correlations(site_id,observed_at)",
            "CREATE INDEX idx_perimeter_host_device_seen ON perimeter_host_correlations(device_id,observed_at)",
            "CREATE INDEX idx_perimeter_host_destination ON perimeter_host_correlations(destination_ip,destination_port,observed_at)",
        ),
    ),

    (
        37,
        (
            """CREATE TABLE external_exposures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                scope_type TEXT NOT NULL CHECK (scope_type IN ('PUBLIC_IPV4','PUBLIC_CIDR','HOSTNAME')),
                canonical_target TEXT NOT NULL,
                device_id INTEGER NOT NULL REFERENCES devices(id),
                target_ip TEXT NOT NULL,
                port_number INTEGER NOT NULL CHECK (port_number BETWEEN 1 AND 65535),
                transport TEXT NOT NULL CHECK (transport = 'tcp'),
                service_name TEXT,
                product TEXT,
                version TEXT,
                extra_info TEXT,
                service_confidence TEXT CHECK (service_confidence IS NULL OR service_confidence IN ('LOW','MEDIUM','HIGH')),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_observation_source TEXT NOT NULL,
                last_scanner TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE external_exposure_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observation_key TEXT NOT NULL UNIQUE,
                exposure_id INTEGER NOT NULL REFERENCES external_exposures(id) ON DELETE CASCADE,
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                device_id INTEGER NOT NULL REFERENCES devices(id),
                target_ip TEXT NOT NULL,
                port_number INTEGER NOT NULL CHECK (port_number BETWEEN 1 AND 65535),
                transport TEXT NOT NULL CHECK (transport = 'tcp'),
                service_name TEXT,
                product TEXT,
                version TEXT,
                extra_info TEXT,
                service_confidence TEXT CHECK (service_confidence IS NULL OR service_confidence IN ('LOW','MEDIUM','HIGH')),
                observed_at TEXT NOT NULL,
                source TEXT NOT NULL,
                scanner TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            "CREATE INDEX idx_external_exposures_scope_seen ON external_exposures(scope_id,last_seen)",
            "CREATE INDEX idx_external_exposures_device_seen ON external_exposures(device_id,last_seen)",
            "CREATE INDEX idx_external_exposures_target_port ON external_exposures(target_ip,port_number,transport)",
            "CREATE INDEX idx_external_exposure_observations_exposure_seen ON external_exposure_observations(exposure_id,observed_at)",
        ),
    ),

    (
        38,
        (
            """CREATE TABLE external_exposure_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_id INTEGER NOT NULL UNIQUE REFERENCES authorized_scopes(id) ON DELETE CASCADE,
                policy_mode TEXT NOT NULL CHECK (policy_mode = 'ALLOWLIST'),
                expected_tcp_ports_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE external_exposure_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exposure_id INTEGER NOT NULL UNIQUE REFERENCES external_exposures(id) ON DELETE CASCADE,
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                policy_id INTEGER REFERENCES external_exposure_policies(id) ON DELETE SET NULL,
                classification TEXT NOT NULL CHECK (classification IN ('EXPECTED','UNEXPECTED','REVIEW')),
                reason TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                assessed_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """INSERT INTO external_exposure_assessments (
                exposure_id, scope_id, policy_id, classification, reason, rule_id, rule_version,
                assessed_at, created_at, updated_at
            )
            SELECT id, scope_id, NULL, 'REVIEW',
                   'No explicit expected-port policy exists for this authorized public scope.',
                   'NO_EXPLICIT_EXPOSURE_POLICY', '12B-1', updated_at, updated_at, updated_at
            FROM external_exposures""",
            "CREATE INDEX idx_external_exposure_assessments_scope_class ON external_exposure_assessments(scope_id,classification,assessed_at)",
            "CREATE INDEX idx_external_exposure_assessments_policy ON external_exposure_assessments(policy_id)",
        ),
    ),

    (
        39,
        (
            """CREATE TABLE external_exposure_classifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exposure_id INTEGER NOT NULL UNIQUE REFERENCES external_exposures(id) ON DELETE CASCADE,
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                service_role TEXT NOT NULL CHECK (service_role IN ('REMOTE_ADMIN','WEB','FILE_SHARING','DATABASE','MAIL','DNS','VPN','OTHER','UNKNOWN')),
                exposure_profile TEXT NOT NULL CHECK (exposure_profile IN ('COMMON_PUBLIC_SERVICE','SENSITIVE_ADMIN_SERVICE','INTERNAL_STYLE_SERVICE','UNKNOWN_SERVICE')),
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                reason TEXT NOT NULL,
                classified_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """INSERT INTO external_exposure_classifications (
                exposure_id, scope_id, service_role, exposure_profile, rule_id, rule_version, reason,
                classified_at, created_at, updated_at
            )
            SELECT id, scope_id,
                CASE
                    WHEN port_number IN (22,23,3389,5900,5985,5986) THEN 'REMOTE_ADMIN'
                    WHEN port_number IN (80,443,8080,8443) THEN 'WEB'
                    WHEN port_number IN (20,21,139,445,2049) THEN 'FILE_SHARING'
                    WHEN port_number IN (1433,1521,3306,5432,6379,27017) THEN 'DATABASE'
                    WHEN port_number IN (25,110,143,465,587,993,995) THEN 'MAIL'
                    WHEN port_number = 53 THEN 'DNS'
                    WHEN port_number IN (500,1194,1701,1723,4500,51820) THEN 'VPN'
                    WHEN service_name IS NOT NULL THEN 'OTHER'
                    ELSE 'UNKNOWN'
                END,
                CASE
                    WHEN port_number IN (22,23,3389,5900,5985,5986) THEN 'SENSITIVE_ADMIN_SERVICE'
                    WHEN port_number IN (20,21,139,445,2049,1433,1521,3306,5432,6379,27017) THEN 'INTERNAL_STYLE_SERVICE'
                    WHEN port_number IN (25,53,80,110,143,443,465,500,587,993,995,1194,1701,1723,4500,8080,8443,51820) THEN 'COMMON_PUBLIC_SERVICE'
                    ELSE 'UNKNOWN_SERVICE'
                END,
                'MIGRATION_PORT_ROLE_MAP', '12C-1',
                'Existing authorized public TCP exposure classified deterministically from persisted port/service identity; this is not a vulnerability finding.',
                updated_at, updated_at, updated_at
            FROM external_exposures""",
            "CREATE INDEX idx_external_exposure_classifications_scope_role ON external_exposure_classifications(scope_id,service_role,classified_at)",
            "CREATE INDEX idx_external_exposure_classifications_profile ON external_exposure_classifications(exposure_profile,classified_at)",
        ),
    ),

    (
        40,
        (
            """CREATE TABLE external_exposure_presence (
                exposure_id INTEGER PRIMARY KEY REFERENCES external_exposures(id) ON DELETE CASCADE,
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                presence_state TEXT NOT NULL CHECK (presence_state IN ('PRESENT','ABSENT')),
                last_present_at TEXT,
                last_absent_at TEXT,
                changed_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """INSERT INTO external_exposure_presence (
                exposure_id, scope_id, presence_state, last_present_at, last_absent_at,
                changed_at, created_at, updated_at
            )
            SELECT id, scope_id, 'PRESENT', last_seen, NULL, updated_at, updated_at, updated_at
            FROM external_exposures""",
            """CREATE TABLE external_exposure_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                exposure_id INTEGER NOT NULL REFERENCES external_exposures(id) ON DELETE CASCADE,
                scope_id INTEGER NOT NULL REFERENCES authorized_scopes(id),
                change_type TEXT NOT NULL CHECK (change_type IN (
                    'NEW_EXPOSURE','SERVICE_CHANGED','FINGERPRINT_CHANGED',
                    'EXPOSURE_DISAPPEARED','EXPOSURE_REAPPEARED'
                )),
                previous_value TEXT,
                current_value TEXT,
                reason TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                source TEXT NOT NULL,
                scanner TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            "CREATE INDEX idx_external_exposure_presence_scope_state ON external_exposure_presence(scope_id,presence_state,changed_at)",
            "CREATE INDEX idx_external_exposure_changes_scope_type_seen ON external_exposure_changes(scope_id,change_type,observed_at)",
            "CREATE INDEX idx_external_exposure_changes_exposure_seen ON external_exposure_changes(exposure_id,observed_at)",
        ),
    ),

    (
        41,
        (
            """CREATE TABLE incident_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_key TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
                summary TEXT NOT NULL DEFAULT '' CHECK (length(summary) <= 4000),
                state TEXT NOT NULL CHECK (state IN ('OPEN','IN_REVIEW','CLOSED')),
                priority TEXT NOT NULL CHECK (priority IN ('LOW','MEDIUM','HIGH','CRITICAL')),
                confidence TEXT NOT NULL CHECK (confidence IN ('LOW','MEDIUM','HIGH')),
                site_id INTEGER REFERENCES sites(id),
                scope_id INTEGER REFERENCES authorized_scopes(id),
                device_id INTEGER REFERENCES devices(id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                first_evidence_at TEXT,
                last_evidence_at TEXT,
                closed_at TEXT,
                disposition TEXT NOT NULL CHECK (disposition IN (
                    'UNREVIEWED','EXPECTED_ACTIVITY','BENIGN','NEEDS_MONITORING',
                    'ACTION_REQUIRED','FALSE_POSITIVE','INCONCLUSIVE')),
                analyst_note TEXT CHECK (analyst_note IS NULL OR length(analyst_note) <= 4000),
                CHECK ((state = 'CLOSED' AND closed_at IS NOT NULL)
                    OR (state != 'CLOSED' AND closed_at IS NULL))
            )""",
            """CREATE TABLE incident_review_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL REFERENCES incident_reviews(id) ON DELETE CASCADE,
                evidence_type TEXT NOT NULL CHECK (evidence_type IN (
                    'PERIMETER_DETECTION','PERIMETER_POLICY_CORRELATION',
                    'PERIMETER_HOST_CORRELATION','EXTERNAL_EXPOSURE_CHANGE',
                    'THREAT_DETECTION','THREAT_CORRELATION','WEB_DETECTION')),
                evidence_id INTEGER NOT NULL CHECK (evidence_id > 0),
                observed_at TEXT NOT NULL,
                added_at TEXT NOT NULL,
                reason TEXT CHECK (reason IS NULL OR length(reason) <= 500),
                UNIQUE (incident_id, evidence_type, evidence_id)
            )""",
            "CREATE INDEX idx_incident_reviews_state_priority ON incident_reviews(state,priority,updated_at)",
            "CREATE INDEX idx_incident_reviews_site ON incident_reviews(site_id,updated_at)",
            "CREATE INDEX idx_incident_reviews_scope ON incident_reviews(scope_id,updated_at)",
            "CREATE INDEX idx_incident_reviews_device ON incident_reviews(device_id,updated_at)",
            "CREATE INDEX idx_incident_review_evidence_source ON incident_review_evidence(evidence_type,evidence_id)",
            "CREATE INDEX idx_incident_review_evidence_time ON incident_review_evidence(incident_id,observed_at)",
        ),
    ),

    (
        42,
        (
            """CREATE TABLE incident_review_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_review_id INTEGER NOT NULL REFERENCES incident_reviews(id) ON DELETE CASCADE,
                note_text TEXT NOT NULL CHECK (length(note_text) BETWEEN 1 AND 4000),
                actor_source TEXT NOT NULL CHECK (actor_source = 'OPERATOR'),
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE incident_review_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_review_id INTEGER NOT NULL REFERENCES incident_reviews(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL CHECK (event_type IN (
                    'REVIEW_CREATED','STATE_CHANGED','REVIEW_CLOSED','REVIEW_REOPENED',
                    'PRIORITY_CHANGED','CONFIDENCE_CHANGED','DISPOSITION_CHANGED',
                    'REVIEW_FIELD_CHANGED','ANALYST_NOTE_ADDED','ANALYST_NOTE_CLEARED',
                    'EVIDENCE_ATTACHED','EVIDENCE_DETACHED')),
                actor_source TEXT NOT NULL CHECK (actor_source = 'OPERATOR'),
                created_at TEXT NOT NULL,
                field_name TEXT CHECK (field_name IS NULL OR field_name IN (
                    'state','priority','confidence','disposition','analyst_note',
                    'title','summary','site_id','scope_id','device_id')),
                old_value TEXT CHECK (old_value IS NULL OR length(old_value) <= 4000),
                new_value TEXT CHECK (new_value IS NULL OR length(new_value) <= 4000),
                evidence_type TEXT CHECK (evidence_type IS NULL OR evidence_type IN (
                    'PERIMETER_DETECTION','PERIMETER_POLICY_CORRELATION',
                    'PERIMETER_HOST_CORRELATION','EXTERNAL_EXPOSURE_CHANGE',
                    'THREAT_DETECTION','THREAT_CORRELATION','WEB_DETECTION')),
                evidence_id INTEGER CHECK (evidence_id IS NULL OR evidence_id > 0),
                note_id INTEGER REFERENCES incident_review_notes(id),
                summary TEXT CHECK (summary IS NULL OR length(summary) <= 240),
                CHECK ((evidence_type IS NULL) = (evidence_id IS NULL))
            )""",
            "CREATE INDEX idx_incident_review_events_timeline ON incident_review_events(incident_review_id,created_at,id)",
            "CREATE INDEX idx_incident_review_notes_timeline ON incident_review_notes(incident_review_id,created_at,id)",
            "CREATE TRIGGER incident_review_events_no_update BEFORE UPDATE ON incident_review_events BEGIN SELECT RAISE(ABORT,'incident review events are append-only'); END",
            "CREATE TRIGGER incident_review_events_no_delete BEFORE DELETE ON incident_review_events BEGIN SELECT RAISE(ABORT,'incident review events are append-only'); END",
            "CREATE TRIGGER incident_review_notes_no_update BEFORE UPDATE ON incident_review_notes BEGIN SELECT RAISE(ABORT,'incident review notes are append-only'); END",
            "CREATE TRIGGER incident_review_notes_no_delete BEFORE DELETE ON incident_review_notes BEGIN SELECT RAISE(ABORT,'incident review notes are append-only'); END",
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
