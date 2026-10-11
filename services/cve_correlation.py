from collections.abc import Iterable
from datetime import datetime

from database import cves as cves_db
from database import findings as findings_db
from database.db import DB_PATH
from services.cve_matcher import CveMatcher, MATCHER_ID
from services.cve_models import (
    CveMatch,
    CveMatchConfidence,
    CveMatchStatus,
    CveRecord,
    CveServiceEvidence,
)
from services.finding_models import FindingConfidence, FindingRecord, FindingSeverity, FindingStatus


class CveCorrelationError(ValueError):
    """Raised when local CVE correlation input is invalid."""


def _record_from_row(row: dict) -> CveRecord:
    return CveRecord(
        record_id=row["id"],
        cve_id=row["cve_id"],
        source=row["source"],
        source_reference=row["source_reference"],
        product=row["product"],
        vendor=row["vendor"],
        affected_version_expression=row["version_expression"],
        description=row["description"],
        severity=row["severity"],
        cvss_score=row["cvss_score"],
        metadata=row.get("metadata"),
    )


class CveCorrelationService:
    def __init__(self, db_path=DB_PATH, matcher: CveMatcher | None = None):
        self.db_path = db_path
        self.matcher = matcher or CveMatcher()

    def correlate(
        self,
        evidence: CveServiceEvidence,
        records: Iterable[CveRecord],
    ) -> list[dict]:
        if not isinstance(evidence, CveServiceEvidence):
            raise CveCorrelationError("Normalized service evidence is required.")

        matches = []

        for supplied_record in records:
            if not isinstance(supplied_record, CveRecord):
                raise CveCorrelationError("CVE records must be CveRecord objects.")

            stored = cves_db.get_cve_record_by_identity(
                supplied_record.source,
                supplied_record.cve_id,
                supplied_record.product,
                supplied_record.affected_version_expression,
                self.db_path,
            )
            if stored is None:
                stored = cves_db.create_cve_record(supplied_record, self.db_path)

            stored_record = _record_from_row(stored)
            match = self.matcher.match(
                evidence,
                stored_record,
                stored["id"],
            )
            if match is None:
                continue

            existing = cves_db.get_cve_match_by_stable_key(
                match.stable_key,
                self.db_path,
            )
            if existing is not None:
                current = cves_db.touch_cve_match(
                    existing["id"],
                    evidence.observed_at,
                    self.db_path,
                )
                self._touch_review_finding(current)
                matches.append(current)
                continue

            current = cves_db.create_cve_match(match, self.db_path)
            self._create_review_finding(current, match)
            matches.append(cves_db.get_cve_match(current["id"], self.db_path))

        return matches

    def _create_review_finding(self, stored_match: dict, match: CveMatch):
        if match.status not in {
            CveMatchStatus.REVIEW,
            CveMatchStatus.POSSIBLE_MATCH,
        }:
            return

        stable_key = f"cve-review:{match.stable_key}"
        if findings_db.get_finding_by_stable_key(stable_key, self.db_path) is not None:
            return

        severity = (
            FindingSeverity.MEDIUM
            if match.status is CveMatchStatus.REVIEW
            else FindingSeverity.LOW
        )
        confidence = FindingConfidence(match.confidence.value)
        now = match.last_seen
        finding = FindingRecord(
            finding_type="CVE_REVIEW",
            device_id=match.device_id,
            network_id=self._network_id_for_match(match),
            port_id=match.port_id,
            service_id=match.service_id,
            severity=severity,
            confidence=confidence,
            status=FindingStatus.OPEN,
            title="Possible CVE match requires review",
            reason=match.match_reason,
            recommendation="Review the observed product/version evidence against the local CVE record.",
            evidence_type="CVE_CORRELATION",
            source="cve-correlation",
            rule_id=MATCHER_ID,
            rule_version="1",
            stable_key=stable_key,
            first_seen=now,
            last_seen=now,
            metadata={"cve_id": match.cve_id, "cve_match_id": stored_match["id"]},
        )
        finding_row = findings_db.create_finding(finding, self.db_path)
        cves_db.update_cve_match_finding(
            stored_match["id"],
            finding_row["id"],
            self.db_path,
        )

    def _touch_review_finding(self, stored_match: dict):
        finding_id = stored_match.get("finding_id")
        if finding_id is not None:
            findings_db.touch_finding(
                finding_id,
                datetime.fromisoformat(stored_match["last_seen"]),
                self.db_path,
            )

    def _network_id_for_match(self, match: CveMatch) -> int:
        from database.inventory import get_device

        device = get_device(match.device_id, self.db_path)
        if device is None:
            raise CveCorrelationError("Matched device no longer exists.")
        return device["network_id"]