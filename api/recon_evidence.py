import base64
import binascii
import sqlite3
from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from api.remote_sensors import local_management
from database.db import get_connection, initialize_database
from database.inventory import get_device
from database.findings import list_device_findings

MAX_IMAGE_BYTES = 1_048_576
MAX_IMAGES_PER_DEVICE = 20

class EvidenceCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    filename: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=500)
    image_base64: str = Field(min_length=1, max_length=1_400_000)
    finding_id: int | None = Field(default=None, gt=0)


def ensure_table(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS recon_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        finding_id INTEGER,
        filename TEXT NOT NULL,
        description TEXT NOT NULL,
        media_type TEXT NOT NULL,
        image_data BLOB NOT NULL,
        created_at TEXT NOT NULL
    )""")


def verify_image(raw):
    if raw.startswith(b'\x89PNG\r\n\x1a\n') and len(raw) >= 24:
        return 'image/png'
    if raw.startswith(b'\xff\xd8\xff') and raw.endswith(b'\xff\xd9'):
        return 'image/jpeg'
    raise HTTPException(422, 'Only genuine PNG or JPEG screenshots are accepted.')


def serialize(row, include_image=False):
    item = dict(row)
    if include_image:
        item['image_base64'] = base64.b64encode(item.pop('image_data')).decode('ascii')
    return item


def register_recon_evidence_routes(app: FastAPI, db_path_provider: Callable):
    def connect():
        path = db_path_provider()
        initialize_database(path)
        return get_connection(path)

    def verify_device(device_id, db_path):
        if get_device(device_id, db_path=db_path) is None:
            raise HTTPException(404, 'Device not found.')

    @app.get('/recon/devices/{device_id}/evidence', dependencies=[Depends(local_management)])
    def list_evidence(device_id: int):
        path = db_path_provider()
        verify_device(device_id, path)
        with connect() as conn:
            conn.row_factory = sqlite3.Row
            ensure_table(conn)
            rows = conn.execute('SELECT id,device_id,finding_id,filename,description,media_type,created_at FROM recon_evidence WHERE device_id=? ORDER BY id DESC LIMIT 20', (device_id,)).fetchall()
            return [dict(row) for row in rows]

    @app.post('/recon/devices/{device_id}/evidence', status_code=201, dependencies=[Depends(local_management)])
    def add_evidence(device_id: int, body: EvidenceCreate):
        path = db_path_provider()
        verify_device(device_id, path)
        if body.finding_id is not None:
            findings = list_device_findings(device_id, db_path=path)
            if not any(f['id'] == body.finding_id for f in findings):
                raise HTTPException(422, 'Finding does not belong to the selected device.')
        try:
            image_data = base64.b64decode(body.image_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(422, 'Invalid screenshot data.') from exc
        if not image_data or len(image_data) > MAX_IMAGE_BYTES:
            raise HTTPException(413, 'Screenshot must be 1 MB or smaller.')
        media_type = verify_image(image_data)
        created_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with connect() as conn:
            conn.row_factory = sqlite3.Row
            ensure_table(conn)
            if conn.execute('SELECT COUNT(*) FROM recon_evidence WHERE device_id=?', (device_id,)).fetchone()[0] >= MAX_IMAGES_PER_DEVICE:
                raise HTTPException(409, 'Screenshot limit reached for this device.')
            cursor = conn.execute('INSERT INTO recon_evidence (device_id,finding_id,filename,description,media_type,image_data,created_at) VALUES (?,?,?,?,?,?,?)', (device_id, body.finding_id, body.filename, body.description, media_type, image_data, created_at))
            conn.commit()
            return {'id': cursor.lastrowid, 'device_id': device_id, 'finding_id': body.finding_id, 'filename': body.filename, 'description': body.description, 'media_type': media_type, 'created_at': created_at}

    @app.get('/recon/devices/{device_id}/evidence/{evidence_id}', dependencies=[Depends(local_management)])
    def get_evidence(device_id: int, evidence_id: int):
        path = db_path_provider()
        verify_device(device_id, path)
        with connect() as conn:
            conn.row_factory = sqlite3.Row
            ensure_table(conn)
            row = conn.execute('SELECT * FROM recon_evidence WHERE id=? AND device_id=?', (evidence_id, device_id)).fetchone()
            if row is None:
                raise HTTPException(404, 'Screenshot not found.')
            return serialize(row, include_image=True)

    @app.delete('/recon/devices/{device_id}/evidence/{evidence_id}', status_code=204, dependencies=[Depends(local_management)])
    def delete_evidence(device_id: int, evidence_id: int):
        path = db_path_provider()
        verify_device(device_id, path)
        with connect() as conn:
            ensure_table(conn)
            deleted = conn.execute('DELETE FROM recon_evidence WHERE id=? AND device_id=?', (evidence_id, device_id)).rowcount
            if not deleted:
                raise HTTPException(404, 'Screenshot not found.')
            conn.commit()
