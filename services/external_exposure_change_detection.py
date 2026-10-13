from database import external_exposure_changes as change_db
from database.db import DB_PATH


CHANGE_RULE_VERSION = "12D-1"


def _fingerprint(exposure: dict) -> tuple:
    return (
        exposure.get("product"), exposure.get("version"), exposure.get("extra_info"),
        exposure.get("service_confidence"),
    )


def _fingerprint_text(exposure: dict) -> str:
    parts = [
        f"product={exposure.get('product') or '-'}",
        f"version={exposure.get('version') or '-'}",
        f"extra={exposure.get('extra_info') or '-'}",
        f"confidence={exposure.get('service_confidence') or '-'}",
    ]
    return ";".join(parts)


def process_observation_change(record: dict, db_path=DB_PATH):
    exposure = record["exposure"]
    previous = record.get("previous_exposure")
    observed = record["observation"]
    if not record.get("observation_inserted"):
        return []

    observed_at = observed["observed_at"]
    source = observed["source"]
    scanner = observed["scanner"]
    presence = change_db.get_presence(exposure["id"], db_path)
    changes = []

    # Migration 40 seeds pre-existing exposures as PRESENT. A newly created exposure has no row.
    if presence is None:
        change_db.upsert_presence(
            exposure_id=exposure["id"], scope_id=exposure["scope_id"], state="PRESENT",
            changed_at=observed_at, last_present_at=observed_at, last_absent_at=None,
            db_path=db_path,
        )
        changes.append(change_db.insert_change(
            exposure_id=exposure["id"], scope_id=exposure["scope_id"],
            change_type="NEW_EXPOSURE", observed_at=observed_at,
            previous_value=None, current_value=f"tcp/{exposure['port_number']}",
            reason="A newly observed open TCP endpoint entered the authorized external exposure inventory.",
            source=source, scanner=scanner, db_path=db_path,
        ))
        return changes

    if presence["presence_state"] == "ABSENT":
        change_db.upsert_presence(
            exposure_id=exposure["id"], scope_id=exposure["scope_id"], state="PRESENT",
            changed_at=observed_at, last_present_at=observed_at,
            last_absent_at=presence.get("last_absent_at"), db_path=db_path,
        )
        changes.append(change_db.insert_change(
            exposure_id=exposure["id"], scope_id=exposure["scope_id"],
            change_type="EXPOSURE_REAPPEARED", observed_at=observed_at,
            previous_value="ABSENT", current_value="PRESENT",
            reason="A previously absent endpoint was observed open again by a completed authorized service scan.",
            source=source, scanner=scanner, db_path=db_path,
        ))
    else:
        change_db.upsert_presence(
            exposure_id=exposure["id"], scope_id=exposure["scope_id"], state="PRESENT",
            changed_at=presence["changed_at"], last_present_at=observed_at,
            last_absent_at=presence.get("last_absent_at"), db_path=db_path,
        )

    if previous is None or observed_at < previous["last_seen"]:
        return changes

    old_service = previous.get("service_name")
    new_service = exposure.get("service_name")
    if old_service and new_service and old_service != new_service:
        changes.append(change_db.insert_change(
            exposure_id=exposure["id"], scope_id=exposure["scope_id"],
            change_type="SERVICE_CHANGED", observed_at=observed_at,
            previous_value=old_service, current_value=new_service,
            reason="The normalized service identity changed on the same authorized external TCP endpoint.",
            source=source, scanner=scanner, db_path=db_path,
        ))
    elif _fingerprint(previous) != _fingerprint(exposure):
        changes.append(change_db.insert_change(
            exposure_id=exposure["id"], scope_id=exposure["scope_id"],
            change_type="FINGERPRINT_CHANGED", observed_at=observed_at,
            previous_value=_fingerprint_text(previous), current_value=_fingerprint_text(exposure),
            reason="The normalized service fingerprint changed on the same authorized external TCP endpoint.",
            source=source, scanner=scanner, db_path=db_path,
        ))
    return changes


def reconcile_completed_scan(*, scope_id: int, device_id: int, observed_exposure_ids: set[int],
                             completed_at: str, source: str, scanner: str, db_path=DB_PATH):
    changes = []
    for exposure in change_db.list_present_exposures_for_device(
        scope_id=scope_id, device_id=device_id, db_path=db_path
    ):
        if exposure["id"] in observed_exposure_ids:
            continue
        # Do not let an out-of-order older scan mark a newer observation absent.
        if completed_at < exposure["last_seen"]:
            continue
        change_db.upsert_presence(
            exposure_id=exposure["id"], scope_id=scope_id, state="ABSENT",
            changed_at=completed_at, last_present_at=exposure.get("last_present_at") or exposure["last_seen"],
            last_absent_at=completed_at, db_path=db_path,
        )
        changes.append(change_db.insert_change(
            exposure_id=exposure["id"], scope_id=scope_id,
            change_type="EXPOSURE_DISAPPEARED", observed_at=completed_at,
            previous_value="PRESENT", current_value="ABSENT",
            reason="A previously observed endpoint was not open in a completed authorized bounded service scan.",
            source=source, scanner=scanner, db_path=db_path,
        ))
    return changes
