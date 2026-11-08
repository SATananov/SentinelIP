import base64
import sqlite3

import pytest

import api.main as api_main
import api.recon_evidence as evidence_module
from database.db import initialize_database
from fastapi.testclient import TestClient

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 16


@pytest.fixture
def client(monkeypatch, tmp_path):
    db_path = tmp_path / 'recon-evidence-test.sqlite3'
    initialize_database(db_path)
    monkeypatch.setattr(api_main, 'DB_PATH', db_path)
    monkeypatch.setattr(evidence_module, 'get_device', lambda device_id, db_path=None: {'id': device_id} if device_id == 42 else None)
    with TestClient(api_main.app, base_url='http://127.0.0.1:8000', client=('127.0.0.1', 5050)) as test_client:
        yield test_client


def payload(data=PNG, finding_id=None):
    return {'filename': 'evidence.png', 'description': 'Authorized laboratory screenshot', 'image_base64': base64.b64encode(data).decode('ascii'), 'finding_id': finding_id}


def test_create_list_read_and_delete(client):
    created = client.post('/recon/devices/42/evidence', json=payload())
    assert created.status_code == 201
    evidence_id = created.json()['id']
    listed = client.get('/recon/devices/42/evidence')
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert 'image_base64' not in listed.json()[0]
    detail = client.get(f'/recon/devices/42/evidence/{evidence_id}')
    assert detail.status_code == 200
    assert base64.b64decode(detail.json()['image_base64']) == PNG
    assert client.delete(f'/recon/devices/42/evidence/{evidence_id}').status_code == 204
    assert client.get(f'/recon/devices/42/evidence/{evidence_id}').status_code == 404


def test_invalid_image_rejected(client):
    assert client.post('/recon/devices/42/evidence', json=payload(b'not an image')).status_code == 422
    invalid = payload()
    invalid['image_base64'] = 'not base64!'
    assert client.post('/recon/devices/42/evidence', json=invalid).status_code == 422


def test_oversized_image_rejected(client):
    oversized = PNG + b'0' * (1_048_577 - len(PNG))
    assert client.post('/recon/devices/42/evidence', json=payload(oversized)).status_code == 413


def test_unknown_device_rejected(client):
    assert client.post('/recon/devices/999/evidence', json=payload()).status_code == 404
    assert client.get('/recon/devices/999/evidence').status_code == 404


def test_wrong_finding_rejected(client):
    assert client.post('/recon/devices/42/evidence', json=payload(finding_id=999)).status_code == 422


def test_max_evidence_count(client):
    for _ in range(20):
        assert client.post('/recon/devices/42/evidence', json=payload()).status_code == 201
    assert client.post('/recon/devices/42/evidence', json=payload()).status_code == 409
