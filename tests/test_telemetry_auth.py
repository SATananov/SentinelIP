import sqlite3

from database.telemetry import provision_sensor
from services.telemetry_auth import hash_sensor_token, verify_sensor_token


def test_token_hashing_and_sensor_provisioning(tmp_path):
    db_path = tmp_path / "test.db"
    sensor, token = provision_sensor(
        "browser-test",
        "Browser Test",
        "BROWSER",
        None,
        "DOMAIN_ONLY",
        30,
        db_path,
    )

    assert token
    assert sensor["sensor_key"] == "browser-test"
    assert verify_sensor_token(
        token,
        sensor["token_salt"],
        sensor["token_hash"],
        sensor["token_iterations"],
    )
    assert not verify_sensor_token(
        "wrong-token",
        sensor["token_salt"],
        sensor["token_hash"],
        sensor["token_iterations"],
    )

    with sqlite3.connect(db_path) as connection:
        stored = connection.execute(
            "SELECT token_hash FROM telemetry_sensors WHERE id = ?",
            (sensor["id"],),
        ).fetchone()[0]
    assert token not in stored