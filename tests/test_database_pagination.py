from database.db import (
    get_paginated_events,
    initialize_database,
    save_event,
)


def add_event(db_path, index):
    save_event(
        timestamp=f"2026-10-11T10:00:{index:02d}",
        source_ip="10.0.0.1",
        username=None,
        event_type="SSH_PREAUTH",
        severity="INFO",
        message="test event",
        event_count=index,
        db_path=db_path,
    )


def test_get_paginated_events(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    for index in range(1, 6):
        add_event(db_path, index)

    result = get_paginated_events(
        limit=2,
        offset=0,
        db_path=db_path,
    )

    assert result["total"] == 5
    assert len(result["items"]) == 2
    assert result["items"][0]["event_count"] == 5
    assert result["items"][1]["event_count"] == 4

    result = get_paginated_events(
        limit=2,
        offset=2,
        db_path=db_path,
    )

    assert len(result["items"]) == 2
    assert result["items"][0]["event_count"] == 3
    assert result["items"][1]["event_count"] == 2
