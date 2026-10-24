import csv
import io

import api.main as api_main
import services.pdf_report as pdf_report
from services.export_safety import neutralize_csv_cell


def test_csv_formula_neutralization_preserves_original_string():
    cases = {
        "=1+1": "'=1+1",
        "+CMD": "'+CMD",
        "-1+1": "'-1+1",
        "@SUM(A1:A2)": "'@SUM(A1:A2)",
        "\t+CMD": "'\t+CMD",
        "\r=1+1": "'\r=1+1",
        "\n@SUM(A1:A2)": "'\n@SUM(A1:A2)",
        "  =1+1": "'  =1+1",
        "ordinary text": "ordinary text",
        'text, with "quotes"': 'text, with "quotes"',
    }

    for original, expected in cases.items():
        assert neutralize_csv_cell(original) == expected


def test_csv_export_neutralizes_string_fields_and_preserves_csv_cells(monkeypatch):
    event = {
        "id": 7,
        "timestamp": "=1+1",
        "source_ip": "+CMD",
        "username": "\t@SUM(A1:A2)",
        "event_type": "-1+1",
        "severity": "@SUM(A1:A2)",
        "message": '  =1+1, with "quoted" text',
        "event_count": 9,
    }
    monkeypatch.setattr(api_main, "get_bounded_export_events", lambda **_kwargs: [event])

    response = api_main.export_events_csv(time_range="all", from_=None, until=None)
    response_text = response.body.decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(response_text)))

    assert len(rows) == 1
    row = rows[0]
    assert row["timestamp"] == "'=1+1"
    assert row["source_ip"] == "'+CMD"
    assert row["username"] == "'\t@SUM(A1:A2)"
    assert row["event_type"] == "'-1+1"
    assert row["severity"] == "'@SUM(A1:A2)"
    assert row["message"] == "'  =1+1, with \"quoted\" text"
    assert row["id"] == "7"
    assert row["event_count"] == "9"
    assert '"\'  =1+1, with ""quoted"" text"' in response_text


def test_csv_export_keeps_null_username_empty(monkeypatch):
    event = {
        "id": 8,
        "timestamp": "2026-10-24T12:00:00",
        "source_ip": "192.0.2.1",
        "username": None,
        "event_type": "SSH_PREAUTH",
        "severity": "INFO",
        "message": "SSH pre-auth activity",
        "event_count": 1,
    }
    monkeypatch.setattr(api_main, "get_bounded_export_events", lambda **_kwargs: [event])

    response = api_main.export_events_csv(time_range="all", from_=None, until=None)
    row = next(csv.DictReader(io.StringIO(response.body.decode("utf-8"))))

    assert row["username"] == ""


def test_pdf_event_markup_like_text_is_escaped_before_paragraph_parsing(monkeypatch):
    message = (
        '<b>text</b> <font color="red">red</font> & < > '
        '<b>nested <i>looking</b> markup'
    )
    paragraph_inputs = []
    paragraph = pdf_report.Paragraph

    def capture_paragraph(text, style):
        paragraph_inputs.append(text)
        return paragraph(text, style)

    monkeypatch.setattr(pdf_report, "Paragraph", capture_paragraph)
    result = pdf_report.build_security_report(
        events=[{
            "id": 1,
            "timestamp": "2026-10-24T12:00:00",
            "source_ip": "192.0.2.1",
            "username": "analyst",
            "event_type": "SSH_PREAUTH",
            "severity": "ALERT",
            "message": message,
            "event_count": 1,
        }],
    )

    assert result.startswith(b"%PDF")
    captured = "\n".join(paragraph_inputs)
    assert "&lt;b&gt;text&lt;/b&gt;" in captured
    assert '&lt;font color="red"&gt;red&lt;/font&gt;' in captured
    assert "&amp; &lt; &gt;" in captured
    assert "&lt;b&gt;nested &lt;i&gt;looking&lt;/b&gt; markup" in captured
    assert message not in captured
