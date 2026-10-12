"""Privacy-minimal projections of persisted correlation records."""
from services.incident_models import IncidentCorrelation, IncidentError


def load_correlation_projection(connection, correlation_id):
    row = connection.execute("SELECT * FROM correlations WHERE id=?", (correlation_id,)).fetchone()
    if row is None:
        raise IncidentError("Persisted correlation not found.")
    refs = connection.execute(
        "SELECT entity_type, entity_id FROM correlation_entities WHERE correlation_id=? ORDER BY entity_type, entity_id",
        (correlation_id,),
    ).fetchall()
    if len(refs) < 2:
        raise IncidentError("Correlation provenance is incomplete.")
    try:
        return IncidentCorrelation(
            correlation_id=row["id"], correlation_type=row["correlation_type"], state=row["state"],
            severity=row["severity"], confidence=row["confidence"], first_seen=row["first_seen"],
            last_seen=row["last_seen"], reason=row["reason"], rule_id=row["rule_id"], rule_version=row["rule_version"],
            entity_refs=tuple((item["entity_type"], item["entity_id"]) for item in refs),
            device_id=row["device_id"], sensor_id=row["sensor_id"], source_ip=row["source_ip"], hostname=row["hostname"],
        )
    except (ValueError, TypeError) as exc:
        raise IncidentError("Persisted correlation projection is invalid.") from exc
