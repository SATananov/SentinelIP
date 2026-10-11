from fastapi.testclient import TestClient

from api.main import app
from services.pdf_report import build_security_report


client = TestClient(app)


def test_build_security_report_returns_pdf():
    events = [
        {
            "id": 1,
            "timestamp": "2026-10-11T10:00:00",
            "source_ip": "10.0.0.1",
            "username": "tester",
            "event_type": "SSH_PREAUTH",
            "severity": "ALERT",
            "message": "Possible SSH scan",
            "event_count": 5,
        }
    ]

    result = build_security_report(
        events=events,
        severity="ALERT",
        source_ip="10.0.0.1",
        time_range="all",
    )

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF")
    assert b"%%EOF" in result[-1024:]
    assert len(result) > 1000


def test_build_security_report_handles_empty_events():
    result = build_security_report(
        events=[],
        time_range="15m",
    )

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF")
    assert len(result) > 1000


def test_pdf_report_endpoint():
    response = client.get(
        "/export/report.pdf?time_range=all"
    )

    assert response.status_code == 200

    assert response.headers[
        "content-type"
    ].startswith("application/pdf")

    assert "attachment;" in response.headers[
        "content-disposition"
    ]

    assert "sentinelip-security-report-" in response.headers[
        "content-disposition"
    ]

    assert response.content.startswith(b"%PDF")
    assert b"%%EOF" in response.content[-1024:]
    assert len(response.content) > 1000


def test_pdf_report_accepts_filters():
    response = client.get(
        "/export/report.pdf"
        "?severity=ALERT"
        "&source_ip=192.168.122.1"
        "&time_range=all"
    )

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")


def test_pdf_report_rejects_invalid_severity():
    response = client.get(
        "/export/report.pdf"
        "?severity=CRITICAL"
    )

    assert response.status_code == 422


def test_pdf_report_rejects_invalid_time_range():
    response = client.get(
        "/export/report.pdf"
        "?time_range=7d"
    )

    assert response.status_code == 422
