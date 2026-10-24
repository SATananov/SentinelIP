from collections import Counter
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _safe(value):
    if value is None:
        return "-"
    return str(value)


def _paragraph_text(value):
    """Render a dynamic value as literal Paragraph text, never as markup."""
    return escape(_safe(value))


def _report_timestamp():
    return datetime.now().isoformat(timespec="seconds")


def _severity_counts(events):
    counts = Counter(
        event["severity"]
        for event in events
    )

    return {
        "INFO": counts.get("INFO", 0),
        "WARNING": counts.get("WARNING", 0),
        "ALERT": counts.get("ALERT", 0),
    }


def _top_source_ips(events, limit=5):
    counts = Counter(
        event["source_ip"]
        for event in events
    )

    return counts.most_common(limit)


def _event_type_counts(events):
    counts = Counter(
        event["event_type"]
        for event in events
    )

    return counts.most_common()


def build_security_report(
    events,
    severity=None,
    source_ip=None,
    time_range="all",
):
    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=landscape(A4),
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="SentinelIP Security Report",
        author="SentinelIP",
        subject="SSH security monitoring report",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SentinelIPTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "SentinelIPSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#555555"),
        spaceAfter=14,
    )

    heading_style = ParagraphStyle(
        "SentinelIPHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        spaceBefore=8,
        spaceAfter=7,
    )

    normal_style = ParagraphStyle(
        "SentinelIPNormal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
    )

    small_style = ParagraphStyle(
        "SentinelIPSmall",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=9,
    )

    story = []

    generated_at = _report_timestamp()
    severity_summary = _severity_counts(events)
    top_ips = _top_source_ips(events)
    event_types = _event_type_counts(events)

    story.append(
        Paragraph(
            "SentinelIP Security Report",
            title_style,
        )
    )

    story.append(
        Paragraph(
            (
                "SSH security monitoring and event analysis"
                f"<br/>Generated: {_paragraph_text(generated_at)}"
            ),
            subtitle_style,
        )
    )

    filter_data = [
        ["Filter", "Value"],
        [
            "Severity",
            severity if severity is not None else "All",
        ],
        [
            "Source IP",
            source_ip if source_ip is not None else "All",
        ],
        [
            "Time range",
            time_range,
        ],
    ]

    filter_table = Table(
        filter_data,
        colWidths=[38 * mm, 70 * mm],
    )

    filter_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1F2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor("#B8BEC7"),
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, -1),
                    colors.HexColor("#F4F6F8"),
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(filter_table)
    story.append(Spacer(1, 8 * mm))

    story.append(
        Paragraph(
            "Security Summary",
            heading_style,
        )
    )

    summary_data = [
        [
            "Total Events",
            "INFO",
            "WARNING",
            "ALERT",
        ],
        [
            len(events),
            severity_summary["INFO"],
            severity_summary["WARNING"],
            severity_summary["ALERT"],
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            45 * mm,
            45 * mm,
            45 * mm,
            45 * mm,
        ],
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#111827"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (-1, 1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#B8BEC7"),
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, 1),
                    colors.HexColor("#F4F6F8"),
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 6 * mm))

    story.append(
        Paragraph(
            "Top Source IPs",
            heading_style,
        )
    )

    if top_ips:
        ip_data = [
            ["Source IP", "Events"],
        ]

        for ip, count in top_ips:
            ip_data.append(
                [ip, count]
            )

        ip_table = Table(
            ip_data,
            colWidths=[
                70 * mm,
                35 * mm,
            ],
        )

        ip_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#374151"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#C5CBD3"),
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(ip_table)
    else:
        story.append(
            Paragraph(
                "No source IP data for the selected filters.",
                normal_style,
            )
        )

    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            "Event Types",
            heading_style,
        )
    )

    if event_types:
        event_type_data = [
            ["Event Type", "Events"],
        ]

        for event_type, count in event_types:
            event_type_data.append(
                [event_type, count]
            )

        event_type_table = Table(
            event_type_data,
            colWidths=[
                70 * mm,
                35 * mm,
            ],
        )

        event_type_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#374151"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#C5CBD3"),
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(event_type_table)
    else:
        story.append(
            Paragraph(
                "No event type data for the selected filters.",
                normal_style,
            )
        )

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Event Details",
            heading_style,
        )
    )

    if not events:
        story.append(
            Paragraph(
                "No events match the selected filters.",
                normal_style,
            )
        )
    else:
        event_rows = [
            [
                "ID",
                "Timestamp",
                "Source IP",
                "User",
                "Event Type",
                "Severity",
                "Count",
                "Message",
            ]
        ]

        for event in events:
            event_rows.append(
                [
                    _safe(event["id"]),
                    Paragraph(
                        _paragraph_text(event["timestamp"]),
                        small_style,
                    ),
                    Paragraph(
                        _paragraph_text(event["source_ip"]),
                        small_style,
                    ),
                    Paragraph(
                        _paragraph_text(event["username"]),
                        small_style,
                    ),
                    Paragraph(
                        _paragraph_text(event["event_type"]),
                        small_style,
                    ),
                    _safe(event["severity"]),
                    _safe(event["event_count"]),
                    Paragraph(
                        _paragraph_text(event["message"]),
                        small_style,
                    ),
                ]
            )

        event_table = Table(
            event_rows,
            repeatRows=1,
            colWidths=[
                11 * mm,
                36 * mm,
                30 * mm,
                25 * mm,
                35 * mm,
                22 * mm,
                16 * mm,
                78 * mm,
            ],
        )

        event_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#111827"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, 0),
                        7,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.3,
                        colors.HexColor("#C5CBD3"),
                    ),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [
                            colors.white,
                            colors.HexColor("#F6F7F9"),
                        ],
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        3,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        3,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        story.append(event_table)

    story.append(Spacer(1, 8 * mm))

    story.append(
        Paragraph(
            (
                "Generated automatically by SentinelIP. "
                "This report reflects the selected event filters "
                "at generation time."
            ),
            small_style,
        )
    )

    document.build(story)

    pdf_bytes = output.getvalue()
    output.close()

    return pdf_bytes
