"""Fixed, escaped HTML rendering for the bounded Incident Review report."""

from html import escape


MAX_REPORT_HTML_BYTES = 6 * 1024 * 1024

EVIDENCE_LABELS = {
    "PERIMETER_DETECTION": "Perimeter detection",
    "PERIMETER_POLICY_CORRELATION": "Perimeter policy correlation",
    "PERIMETER_HOST_CORRELATION": "Perimeter host correlation",
    "EXTERNAL_EXPOSURE_CHANGE": "External exposure change",
    "THREAT_DETECTION": "Threat detection",
    "THREAT_CORRELATION": "Threat correlation",
    "WEB_DETECTION": "Web detection",
}

REVIEW_FIELDS = (
    ("title", "Title"), ("state", "State"), ("priority", "Priority"),
    ("confidence", "Confidence"), ("disposition", "Disposition"),
    ("site_id", "Site ID"), ("scope_id", "Scope ID"), ("device_id", "Device ID"),
    ("created_at", "Created at"), ("updated_at", "Updated at"),
    ("closed_at", "Closed at"), ("first_evidence_at", "First evidence at"),
    ("last_evidence_at", "Last evidence at"), ("summary", "Summary"),
    ("final_summary", "Final summary"),
)
EVIDENCE_METADATA = (("site_id", "Site ID"), ("scope_id", "Scope ID"), ("device_id", "Device ID"))


class IncidentReviewReportHtmlError(ValueError):
    """Safe rendering error with an HTTP status suitable for the API layer."""

    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


def _text(value):
    if value is None:
        return "—"
    return escape(str(value), quote=True)


def _field(label, value, *, pre=False):
    if value is None:
        return ""
    css = ' class="pre"' if pre else ""
    return f'<div class="field"><dt>{_text(label)}</dt><dd{css}>{_text(value)}</dd></div>'


def _collection_notice(name, collection):
    total = collection["total"]
    returned = collection["returned"]
    omitted = collection["omitted"]
    notice = f'<p class="collection-count">Returned {_text(returned)} of {_text(total)} {escape(name)}.</p>'
    if collection["truncated"]:
        notice += (f'<p class="truncation">Showing {_text(returned)} of {_text(total)} {escape(name)}; '
                   f'{_text(omitted)} omitted by the report limit.</p>')
    return notice


def _evidence_item(item):
    evidence_type = item.get("evidence_type")
    label = EVIDENCE_LABELS.get(evidence_type, "Evidence reference")
    status = {"AVAILABLE": "Available", "MISSING": "Missing"}.get(item.get("source_status"), "Unknown")
    content = [f'<article class="record"><h3>{_text(label)} <span class="muted">#{_text(item.get("evidence_id"))}</span></h3>']
    content.append('<dl class="details">')
    for key, field_label in (("evidence_type", "Evidence type"), ("evidence_id", "Evidence ID"),
                             ("source_status", "Source status"), ("observed_at", "Observed at"),
                             ("added_at", "Added at")):
        value = item.get(key)
        if key == "source_status":
            value = status
        content.append(_field(field_label, value))
    for key, field_label in EVIDENCE_METADATA:
        if key in item:
            content.append(_field(field_label, item[key]))
    content.append("</dl></article>")
    return "".join(content)


def _note_item(item):
    actor = {"OPERATOR": "Operator"}.get(item.get("actor_source"), item.get("actor_source"))
    return (f'<article class="record"><h3>Note <span class="muted">#{_text(item.get("id"))}</span></h3>'
            '<dl class="details">' + _field("Created at", item.get("created_at")) +
            _field("Source", actor) + '</dl><p class="pre">' + _text(item.get("text")) + "</p></article>")


def _timeline_item(item):
    event = item.get("event_type")
    event_label = event.replace("_", " ").capitalize() if isinstance(event, str) else "Timeline event"
    actor = {"OPERATOR": "Operator"}.get(item.get("actor_source"), item.get("actor_source"))
    content = [f'<article class="record"><h3>{_text(event_label)} <span class="muted">#{_text(item.get("id"))}</span></h3>',
               '<dl class="details">', _field("Occurred at", item.get("created_at")),
               _field("Source", actor), _field("Field", item.get("field_name"))]
    if item.get("evidence_type") is not None:
        evidence_label = EVIDENCE_LABELS.get(item.get("evidence_type"), "Evidence reference")
        content.append(_field("Evidence", f'{evidence_label} #{item.get("evidence_id")}'))
    content.append("</dl>")
    if item.get("summary") is not None:
        content.append(f'<p class="pre">{_text(item.get("summary"))}</p>')
    content.append("</article>")
    return "".join(content)


def render_incident_review_report_html(report):
    """Render only the fixed 20A report projection; this function never accesses storage."""
    review = report["review"]
    review_id = review["id"]
    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>SentinelIP Incident Review {_text(review_id)}</title>",
        "<style>"
        "*{box-sizing:border-box}body{margin:0;background:#eef1f4;color:#17212b;"
        "font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}"
        "main{max-width:980px;margin:2rem auto;padding:2.5rem;background:#fff;box-shadow:0 2px 16px #17212b1a}"
        "header{border-bottom:2px solid #34495e;padding-bottom:1rem;margin-bottom:1.5rem}"
        "h1{font-size:1.7rem;margin:.1rem 0}.brand{font-weight:700;letter-spacing:.04em}"
        "h2{font-size:1.25rem;border-bottom:1px solid #c7d0d8;padding-bottom:.35rem;margin-top:2rem}"
        "h3{font-size:1rem;margin:.1rem 0 .7rem}.muted{color:#586674;font-weight:400}"
        ".notice{color:#43515e}.details{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.6rem 1rem;margin:.5rem 0}"
        ".field dt{font-size:.78rem;font-weight:700;color:#4a5968}.field dd{margin:0;overflow-wrap:anywhere}"
        ".field dd.pre,.pre{white-space:pre-wrap;overflow-wrap:anywhere}.record{border:1px solid #d6dde3;"
        "border-radius:5px;padding:.9rem 1rem;margin:.75rem 0;break-inside:avoid;page-break-inside:avoid}"
        ".record p{margin:.6rem 0 0}.collection-count,.truncation{font-size:.9rem}.truncation{font-weight:700}"
        "@media print{body{background:#fff;color:#000;font-size:10.5pt}main{max-width:none;margin:0;padding:0;box-shadow:none}"
        "h2{break-after:avoid-page}.record{border-color:#999}a{color:inherit;text-decoration:none}}"
        "</style></head><body><main><header><div class=\"brand\">SentinelIP</div>"
        "<h1>Incident Review Report</h1><dl class=\"details\">",
        _field("Review ID", review_id), _field("Review key", review.get("incident_key")),
        _field("Generated at", report.get("generated_at")),
        _field("Report schema version", report.get("report_schema_version")),
        "</dl><p class=\"notice\">This report represents the current Incident Review state at the generation time shown above.</p></header>",
        "<section><h2>Review summary</h2><dl class=\"details\">",
    ]
    for key, label in REVIEW_FIELDS:
        value = review.get(key)
        parts.append(_field(label, value, pre=key in ("summary", "final_summary")))
    parts.append("</dl></section>")

    evidence = report["evidence"]
    parts.extend(("<section><h2>Evidence</h2>", _collection_notice("evidence items", evidence)))
    parts.extend(_evidence_item(item) for item in evidence["items"])
    if not evidence["items"]:
        parts.append('<p class="muted">No linked evidence.</p>')
    parts.append("</section>")

    notes = report["notes"]
    parts.extend(("<section><h2>Notes</h2>", _collection_notice("notes", notes)))
    parts.extend(_note_item(item) for item in notes["items"])
    if not notes["items"]:
        parts.append('<p class="muted">No notes.</p>')
    parts.append("</section>")

    timeline = report["timeline"]
    parts.extend(("<section><h2>Timeline</h2>", _collection_notice("timeline events", timeline)))
    parts.extend(_timeline_item(item) for item in timeline["items"])
    if not timeline["items"]:
        parts.append('<p class="muted">No timeline events.</p>')
    parts.append("</section></main></body></html>")
    document = "".join(parts)
    encoded = document.encode("utf-8")
    if len(encoded) > MAX_REPORT_HTML_BYTES:
        raise IncidentReviewReportHtmlError("Incident review HTML report exceeds the output size limit.", 413)
    return encoded
