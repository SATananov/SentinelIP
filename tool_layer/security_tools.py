"""Read-only adapters over persisted deterministic SentinelIP security state."""

from database.correlations import get_correlation, query_correlations
from database.db import DB_PATH
from database.incidents import get_incident, query_incidents
from database.threats import get_threat, query_threats
from tool_layer.contracts import ToolValidationError


MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20


def _positive_id(value, field_name):
    if type(value) is not int or value <= 0:
        raise ToolValidationError(f"{field_name} must be a positive integer.")
    return value


def _pagination(limit, offset):
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
        raise ToolValidationError("limit must be an integer from 1 to 100.")
    if type(offset) is not int or offset < 0:
        raise ToolValidationError("offset must be a non-negative integer.")
    return limit, offset


def _collection(result):
    return {
        "total": result["total"],
        "count": len(result["items"]),
        "items": result["items"],
    }


class SecurityReadTools:
    """Narrow read-only access to persisted threat/correlation/incident records."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def list_threats(self, limit=DEFAULT_PAGE_SIZE, offset=0):
        limit, offset = _pagination(limit, offset)
        return _collection(
            query_threats(
                limit=limit,
                offset=offset,
                db_path=self.db_path,
            )
        )

    def get_threat(self, threat_id):
        threat_id = _positive_id(threat_id, "threat_id")
        return get_threat(threat_id, db_path=self.db_path)

    def list_correlations(self, limit=DEFAULT_PAGE_SIZE, offset=0):
        limit, offset = _pagination(limit, offset)
        return _collection(
            query_correlations(
                limit=limit,
                offset=offset,
                db_path=self.db_path,
            )
        )

    def get_correlation(self, correlation_id):
        correlation_id = _positive_id(correlation_id, "correlation_id")
        return get_correlation(correlation_id, db_path=self.db_path)

    def list_incidents(self, limit=DEFAULT_PAGE_SIZE, offset=0):
        limit, offset = _pagination(limit, offset)
        return _collection(
            query_incidents(
                limit=limit,
                offset=offset,
                db_path=self.db_path,
            )
        )

    def get_incident(self, incident_id):
        incident_id = _positive_id(incident_id, "incident_id")
        return get_incident(incident_id, db_path=self.db_path)
