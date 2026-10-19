"""TestClient factory for supported direct-loopback operator requests."""
from fastapi.testclient import TestClient


def make_local_test_client(app):
    return TestClient(
        app,
        base_url="http://127.0.0.1:8000",
        client=("127.0.0.1", 5050),
    )
