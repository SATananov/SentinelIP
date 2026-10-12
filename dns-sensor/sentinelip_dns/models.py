from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DnsEvent:
    external_event_id: str
    observed_at: datetime
    queried_domain: str
    query_type: str
    response_status: str
    resolved_addresses: tuple[str, ...]
    resolver: str | None
    ttl: int | None
    source: str

    def payload(self):
        return {
            "external_event_id": self.external_event_id,
            "observed_at": self.observed_at.isoformat(),
            "queried_domain": self.queried_domain,
            "query_type": self.query_type,
            "response_status": self.response_status,
            "resolved_addresses": list(self.resolved_addresses),
            "resolver": self.resolver,
            "ttl": self.ttl,
            "metadata": {"source": self.source},
        }
