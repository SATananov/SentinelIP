"""Typed append-only management change event insertion."""

from datetime import datetime, timezone
import json


EVENT_ENTITY = {
    "SITE_CREATED": "SITE", "SITE_ENABLED": "SITE", "SITE_DISABLED": "SITE",
    "NETWORK_CREATED": "NETWORK", "NETWORK_ENABLED": "NETWORK",
    "NETWORK_DISABLED": "NETWORK", "NETWORK_DELETED": "NETWORK",
    "SCOPE_AUTHORIZED": "SCOPE", "SCOPE_REAUTHORIZED": "SCOPE",
    "EXPOSURE_POLICY_CONFIGURED": "EXTERNAL_EXPOSURE_POLICY",
    "EXPOSURE_POLICY_REMOVED": "EXTERNAL_EXPOSURE_POLICY",
    "ENROLLMENT_ISSUED": "SENSOR_ENROLLMENT", "ENROLLMENT_REVOKED": "SENSOR_ENROLLMENT",
    "ENROLLMENT_CONSUMED": "SENSOR_ENROLLMENT", "SENSOR_REGISTERED": "SENSOR",
    "SENSOR_ENABLED": "SENSOR", "SENSOR_DISABLED": "SENSOR",
    "SENSOR_CREDENTIAL_REVOKED": "SENSOR", "SENSOR_SCOPE_ASSIGNED": "SENSOR_SCOPE_ASSIGNMENT",
    "SENSOR_SCOPE_UNASSIGNED": "SENSOR_SCOPE_ASSIGNMENT", "SENSOR_TASK_CREATED": "SENSOR_TASK",
    "DATA_LIFECYCLE_CLEANUP_EXECUTED": "DATA_LIFECYCLE",
}
ACTORS = {"LOCAL_OPERATOR", "API_CLIENT", "SENSOR"}
EVENT_ACTORS = {
    "SITE_CREATED": "LOCAL_OPERATOR", "SITE_ENABLED": "LOCAL_OPERATOR", "SITE_DISABLED": "LOCAL_OPERATOR",
    "NETWORK_CREATED": "API_CLIENT", "NETWORK_ENABLED": "API_CLIENT",
    "NETWORK_DISABLED": "API_CLIENT", "NETWORK_DELETED": "API_CLIENT",
    "SCOPE_AUTHORIZED": "API_CLIENT", "SCOPE_REAUTHORIZED": "API_CLIENT",
    "EXPOSURE_POLICY_CONFIGURED": "API_CLIENT", "EXPOSURE_POLICY_REMOVED": "API_CLIENT",
    "ENROLLMENT_ISSUED": "LOCAL_OPERATOR", "ENROLLMENT_REVOKED": "LOCAL_OPERATOR",
    "ENROLLMENT_CONSUMED": "SENSOR", "SENSOR_REGISTERED": "SENSOR",
    "SENSOR_ENABLED": "LOCAL_OPERATOR", "SENSOR_DISABLED": "LOCAL_OPERATOR",
    "SENSOR_CREDENTIAL_REVOKED": "LOCAL_OPERATOR",
    "SENSOR_SCOPE_ASSIGNED": "LOCAL_OPERATOR", "SENSOR_SCOPE_UNASSIGNED": "LOCAL_OPERATOR",
    "SENSOR_TASK_CREATED": "LOCAL_OPERATOR", "DATA_LIFECYCLE_CLEANUP_EXECUTED": "LOCAL_OPERATOR",
}
STATES = {"ENABLED", "DISABLED", "AUTHORIZED_ENABLED", "AUTHORIZED_DISABLED",
          "AUTHORIZED", "ISSUED", "REVOKED", "CONSUMED", "REGISTERED", "CREDENTIAL_ACTIVE", "ASSIGNED", "UNASSIGNED",
          "CREATED", "CREDENTIAL_REVOKED"}
STATE_SHAPES = {
    "SITE_CREATED": (None, {"ENABLED", "DISABLED"}),
    "SITE_ENABLED": ({"DISABLED"}, {"ENABLED"}),
    "SITE_DISABLED": ({"ENABLED"}, {"DISABLED"}),
    "NETWORK_CREATED": (None, {"AUTHORIZED_ENABLED", "AUTHORIZED_DISABLED"}),
    "NETWORK_ENABLED": ({"DISABLED"}, {"ENABLED"}),
    "NETWORK_DISABLED": ({"ENABLED"}, {"DISABLED"}),
    "NETWORK_DELETED": ({"ENABLED", "DISABLED"}, None),
    "SCOPE_AUTHORIZED": (None, {"AUTHORIZED"}),
    "SCOPE_REAUTHORIZED": (None, None),
    "ENROLLMENT_ISSUED": (None, {"ISSUED"}),
    "ENROLLMENT_REVOKED": ({"ISSUED", "CONSUMED"}, {"REVOKED"}),
    "ENROLLMENT_CONSUMED": ({"ISSUED"}, {"CONSUMED"}),
    "SENSOR_REGISTERED": (None, {"REGISTERED"}),
    "SENSOR_ENABLED": ({"DISABLED"}, {"ENABLED"}),
    "SENSOR_DISABLED": ({"ENABLED"}, {"DISABLED"}),
    "SENSOR_CREDENTIAL_REVOKED": ({"CREDENTIAL_ACTIVE"}, {"CREDENTIAL_REVOKED"}),
    "SENSOR_SCOPE_ASSIGNED": (None, {"ASSIGNED"}),
    "SENSOR_SCOPE_UNASSIGNED": ({"ASSIGNED"}, {"UNASSIGNED"}),
    "SENSOR_TASK_CREATED": (None, {"CREATED"}),
    "EXPOSURE_POLICY_CONFIGURED": (None, None),
    "EXPOSURE_POLICY_REMOVED": (None, None),
    "DATA_LIFECYCLE_CLEANUP_EXECUTED": (None, None),
}


def _ports(value):
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) > 64:
        raise ValueError("Invalid audit expected TCP ports.")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in value):
        raise ValueError("Invalid audit expected TCP ports.")
    return json.dumps(sorted(set(value)), separators=(",", ":"))


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def record_event(connection, *, event_type, entity_type, entity_id, actor_type,
                 site_id=None, scope_id=None, sensor_id=None,
                 scope_type=None, enrollment_expires_at=None, task_type=None,
                 target_device_id=None,
                 previous_state=None, new_state=None,
                 previous_expected_tcp_ports=None, new_expected_tcp_ports=None,
                 cleanup_data_class=None, cleanup_evaluated_at=None,
                 cleanup_eligible_before=None, cleanup_deleted_count=None,
                 cleanup_protected_count=None, cleanup_remaining_eligible=None,
                 cleanup_batch_limit=None):
    """Validate a fixed event shape and insert it using the mutation's connection."""
    if EVENT_ENTITY.get(event_type) != entity_type:
        raise ValueError("Invalid management audit event/entity pairing.")
    if actor_type not in ACTORS:
        raise ValueError("Invalid management audit actor.")
    if EVENT_ACTORS[event_type] != actor_type:
        raise ValueError("Invalid management audit actor for event.")
    if not isinstance(entity_id, (str, int)) or isinstance(entity_id, bool) or not str(entity_id):
        raise ValueError("Invalid management audit entity ID.")
    if any(value is not None and (type(value) is not int or value <= 0)
           for value in (site_id, scope_id, sensor_id, target_device_id)):
        raise ValueError("Invalid management audit context ID.")
    required_context = {
        "SITE_CREATED": ("site_id",), "SITE_ENABLED": ("site_id",), "SITE_DISABLED": ("site_id",),
        "NETWORK_CREATED": ("scope_id", "scope_type"),
        "SCOPE_AUTHORIZED": ("scope_id",), "SCOPE_REAUTHORIZED": ("scope_id",),
        "EXPOSURE_POLICY_CONFIGURED": ("scope_id",), "EXPOSURE_POLICY_REMOVED": ("scope_id",),
        "ENROLLMENT_ISSUED": ("site_id",), "ENROLLMENT_REVOKED": ("site_id",),
        "ENROLLMENT_CONSUMED": ("site_id", "sensor_id"), "SENSOR_REGISTERED": ("site_id", "sensor_id"),
        "SENSOR_ENABLED": ("site_id", "sensor_id"), "SENSOR_DISABLED": ("site_id", "sensor_id"),
        "SENSOR_CREDENTIAL_REVOKED": ("site_id", "sensor_id"),
        "SENSOR_SCOPE_ASSIGNED": ("site_id", "scope_id", "sensor_id"),
        "SENSOR_SCOPE_UNASSIGNED": ("site_id", "scope_id", "sensor_id"),
        "SENSOR_TASK_CREATED": ("site_id", "scope_id", "sensor_id"),
    }
    if not isinstance(entity_id, (str, int)) or len(str(entity_id)) > 128:
        raise ValueError("Invalid management audit entity ID.")
    if event_type.startswith("SITE_") and str(entity_id) != str(site_id):
        raise ValueError("Site event entity ID must match site ID.")
    if event_type.startswith("SCOPE_") and str(entity_id) != str(scope_id):
        raise ValueError("Scope event entity ID must match scope ID.")
    if event_type.startswith("EXPOSURE_POLICY_") and str(entity_id) != str(scope_id):
        raise ValueError("Exposure policy entity ID must match scope ID.")
    if event_type.startswith("SENSOR_") and event_type != "SENSOR_TASK_CREATED" and entity_type == "SENSOR":
        if str(entity_id) != str(sensor_id):
            raise ValueError("Sensor event entity ID must match sensor ID.")
    if event_type.startswith("ENROLLMENT_") and (type(entity_id) is not int or entity_id <= 0):
        raise ValueError("Enrollment event requires its numeric record ID.")
    if event_type == "DATA_LIFECYCLE_CLEANUP_EXECUTED" and entity_id != "DATA_LIFECYCLE":
        raise ValueError("Lifecycle event has a fixed entity ID.")
    if event_type.startswith("SENSOR_SCOPE_") and entity_id != f"{sensor_id}:{scope_id}":
        raise ValueError("Assignment event entity ID must identify the relationship.")
    for field in required_context.get(event_type, ()):
        if locals()[field] is None:
            raise ValueError(f"Management audit event requires {field}.")
    if scope_type is not None and scope_type not in {"PRIVATE_NETWORK", "PUBLIC_IPV4", "PUBLIC_CIDR", "HOSTNAME"}:
        raise ValueError("Invalid management audit scope type.")
    if event_type in {"SCOPE_AUTHORIZED", "SCOPE_REAUTHORIZED"} and scope_type is None:
        raise ValueError("Scope audit event requires scope type.")
    if event_type == "ENROLLMENT_ISSUED":
        if not isinstance(enrollment_expires_at, str) or not enrollment_expires_at:
            raise ValueError("Enrollment issuance audit requires expiry.")
    elif enrollment_expires_at is not None:
        raise ValueError("Enrollment expiry is only valid for issuance.")
    if event_type == "SENSOR_TASK_CREATED":
        if task_type not in {"DISCOVER_NETWORK", "DISCOVER_SERVICES"}:
            raise ValueError("Task audit requires a supported task type.")
        if (task_type == "DISCOVER_NETWORK" and target_device_id is not None
                or task_type == "DISCOVER_SERVICES" and target_device_id is None):
            raise ValueError("Task audit target does not match task type.")
    elif task_type is not None or target_device_id is not None:
        raise ValueError("Task fields are only valid for task creation.")
    if previous_state is not None and previous_state not in STATES:
        raise ValueError("Invalid management audit previous state.")
    if new_state is not None and new_state not in STATES:
        raise ValueError("Invalid management audit new state.")
    prior_allowed, new_allowed = STATE_SHAPES[event_type]
    if ((prior_allowed is None and previous_state is not None)
            or (prior_allowed is not None and previous_state not in prior_allowed)
            or (new_allowed is None and new_state is not None)
            or (new_allowed is not None and new_state not in new_allowed)):
        raise ValueError("Invalid management audit state transition.")

    policy_event = event_type in {"EXPOSURE_POLICY_CONFIGURED", "EXPOSURE_POLICY_REMOVED"}
    cleanup_event = event_type == "DATA_LIFECYCLE_CLEANUP_EXECUTED"
    if policy_event:
        if event_type == "EXPOSURE_POLICY_CONFIGURED" and new_expected_tcp_ports is None:
            raise ValueError("Configured policy audit requires new ports.")
        if event_type == "EXPOSURE_POLICY_REMOVED" and previous_expected_tcp_ports is None:
            raise ValueError("Removed policy audit requires prior ports.")
    elif previous_expected_tcp_ports is not None or new_expected_tcp_ports is not None:
        raise ValueError("Port arrays are only valid for exposure policy events.")

    cleanup_values = (cleanup_data_class, cleanup_evaluated_at, cleanup_eligible_before,
                      cleanup_deleted_count, cleanup_protected_count,
                      cleanup_remaining_eligible, cleanup_batch_limit)
    if cleanup_event:
        if cleanup_data_class not in {"DNS_OBSERVATIONS", "WEB_OBSERVATIONS"}:
            raise ValueError("Invalid lifecycle cleanup data class.")
        if not isinstance(cleanup_evaluated_at, str) or not cleanup_evaluated_at:
            raise ValueError("Cleanup audit requires evaluated_at.")
        counts = cleanup_values[2:]
        if any(type(value) is not int or value < 0 for value in counts[:-1]) or type(cleanup_batch_limit) is not int or cleanup_batch_limit <= 0:
            raise ValueError("Invalid lifecycle cleanup counts.")
    elif any(value is not None for value in cleanup_values):
        raise ValueError("Cleanup fields are only valid for cleanup events.")

    previous_ports = _ports(previous_expected_tcp_ports) if policy_event else None
    new_ports = _ports(new_expected_tcp_ports) if policy_event else None
    stamp = _utc_now()
    cursor = connection.execute(
        """INSERT INTO management_audit_events (
            event_type,entity_type,entity_id,site_id,scope_id,sensor_id,scope_type,
            enrollment_expires_at,task_type,target_device_id,actor_type,occurred_at,
            previous_state,new_state,previous_expected_tcp_ports,new_expected_tcp_ports,
            cleanup_data_class,cleanup_evaluated_at,cleanup_eligible_before,cleanup_deleted_count,
            cleanup_protected_count,cleanup_remaining_eligible,cleanup_batch_limit
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (event_type, entity_type, str(entity_id), site_id, scope_id, sensor_id, scope_type,
         enrollment_expires_at, task_type, target_device_id, actor_type, stamp,
         previous_state, new_state, previous_ports, new_ports, cleanup_data_class,
         cleanup_evaluated_at, cleanup_eligible_before, cleanup_deleted_count,
         cleanup_protected_count, cleanup_remaining_eligible, cleanup_batch_limit),
    )
    return cursor.lastrowid
