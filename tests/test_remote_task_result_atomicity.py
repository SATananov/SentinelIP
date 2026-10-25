from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
import json
import sqlite3

import pytest
from fastapi import HTTPException

from api import remote_tasks as remote_task_api
from database.db import get_connection
from database.inventory import create_device
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.remote_tasks import RemoteTaskStore
from database.scopes import get_scope_for_network
from services.remote_sensor_models import Capability


NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)


@pytest.fixture
def result_context(tmp_path):
    db_path = tmp_path / "remote-result.db"
    clock = [NOW]
    store = RemoteSensorStore(db_path, clock=lambda: clock[0])
    site = store.create_site("Result Test")
    enrollment = store.create_enrollment(site["id"])
    issued = store.consume_enrollment(
        enrollment.secret, name="Sensor", platform="linux", version="1",
        reported_capabilities=[Capability.HOST_DISCOVERY.value, Capability.SERVICE_DISCOVERY.value],
    )
    network = create_network(
        "192.168.1.0/24", "Test LAN", "", True, True, db_path
    )
    scope = get_scope_for_network(network["id"], db_path)
    store.assign_scope(issued.record["id"], scope["id"])
    device = create_device(
        stable_key=f"network:{network['id']}:ip:192.168.1.20",
        network_id=network["id"], mac_address=None, hostname="host", vendor=None,
        first_seen=NOW.isoformat(), last_seen=NOW.isoformat(),
        last_ip_address="192.168.1.20", status="ONLINE", identity_confidence="LOW",
        db_path=db_path,
    )
    tasks = RemoteTaskStore(store)
    return {"path": db_path, "store": store, "tasks": tasks, "sensor": issued.record,
            "scope": scope, "device": device, "clock": clock}


def running_task(context, task_type="DISCOVER_NETWORK"):
    task = context["tasks"].create_task(
        context["sensor"]["id"], context["scope"]["id"], task_type,
        device_id=context["device"]["id"] if task_type == "DISCOVER_SERVICES" else None,
    )
    context["tasks"].claim_next(context["sensor"]["id"])
    context["tasks"].transition(context["sensor"]["id"], task["id"], "start")
    return task["id"]


def host_body(ip="192.168.1.55"):
    return remote_task_api.NetworkResult(
        task_type="DISCOVER_NETWORK",
        observations=[{"ip_address": ip, "hostname": "sensor-host"}],
    )


def service_body(product="OpenSSH"):
    return remote_task_api.ServicesResult(
        task_type="DISCOVER_SERVICES", ports=[{"port": 22}],
        services=[{"port": 22, "service_name": "ssh", "product": product,
                   "version": "9.8", "extra_info": None}],
    )


def submit(context, task_id, body):
    return remote_task_api._process_task_result(
        context["store"], context["tasks"], context["sensor"]["id"], task_id, body
    )


def task_state(context, task_id):
    with get_connection(context["path"]) as connection:
        return connection.execute(
            "SELECT status,result_digest,error_code FROM remote_sensor_tasks WHERE id=?",
            (task_id,),
        ).fetchone()


def counts(context):
    with get_connection(context["path"]) as connection:
        return tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("devices", "device_observations", "ports",
                                   "port_observations", "services", "service_observations", "changes"))


def test_identical_completed_replay_is_noop_and_different_digest_conflicts(result_context):
    task_id = running_task(result_context)
    body = host_body()
    first = submit(result_context, task_id, body)
    before = counts(result_context)
    duplicate = submit(result_context, task_id, body)
    assert first == {"task_id": task_id, "status": "COMPLETED", "device_count": 1}
    assert duplicate == {"task_id": task_id, "status": "COMPLETED", "duplicate": True}
    assert counts(result_context) == before

    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body("192.168.1.56"))
    assert exc.value.status_code == 409
    assert counts(result_context) == before
    assert task_state(result_context, task_id)[0] == "COMPLETED"


def test_identical_service_replay_does_not_duplicate_observations_or_changes(result_context):
    task_id = running_task(result_context, "DISCOVER_SERVICES")
    body = service_body()
    first = submit(result_context, task_id, body)
    before = counts(result_context)
    duplicate = submit(result_context, task_id, body)
    assert first == {
        "task_id": task_id, "status": "COMPLETED", "port_count": 1,
        "service_count": 1,
    }
    assert duplicate == {"task_id": task_id, "status": "COMPLETED", "duplicate": True}
    assert counts(result_context) == before
    assert before[3] == 1 and before[5] == 1


@pytest.mark.parametrize("task_type", ["DISCOVER_NETWORK", "DISCOVER_SERVICES"])
def test_inventory_failure_rolls_back_digest_and_same_task_retry_succeeds(
    result_context, monkeypatch, task_type
):
    task_id = running_task(result_context, task_type)
    body = host_body() if task_type == "DISCOVER_NETWORK" else service_body()
    module = remote_task_api.DeviceInventoryService if task_type == "DISCOVER_NETWORK" else remote_task_api.ServiceInventoryService
    method_name = "process_scan" if task_type == "DISCOVER_NETWORK" else "process_result"
    real_method = getattr(module, method_name)
    failed_once = False

    def fail_once(*args, **kwargs):
        nonlocal failed_once
        if not failed_once:
            failed_once = True
            real_method(*args, **kwargs)
            raise sqlite3.OperationalError("injected storage failure")
        return real_method(*args, **kwargs)

    monkeypatch.setattr(module, method_name, fail_once)
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, body)
    assert exc.value.status_code == 503
    assert task_state(result_context, task_id) == ("RUNNING", None, None)
    assert counts(result_context) == before

    response = submit(result_context, task_id, body)
    assert response["status"] == "COMPLETED"
    canonical = json.dumps(body.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    assert task_state(result_context, task_id) == (
        "COMPLETED", sha256(canonical.encode()).hexdigest(), None
    )
    after = counts(result_context)
    if task_type == "DISCOVER_NETWORK":
        assert after == (before[0] + 1, before[1] + 1, *before[2:-1], before[-1] + 2)
    else:
        assert after == (
            before[0], before[1], before[2] + 1, before[3] + 1,
            before[4] + 1, before[5] + 1, before[6] + 2,
        )


def test_completion_update_failure_rolls_back_inventory_and_digest(result_context, monkeypatch):
    task_id = running_task(result_context)
    real_complete = result_context["tasks"].complete_result_in_transaction

    def fail_after_complete(*args, **kwargs):
        real_complete(*args, **kwargs)
        raise sqlite3.OperationalError("injected completion failure")

    monkeypatch.setattr(result_context["tasks"], "complete_result_in_transaction", fail_after_complete)
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 503
    assert task_state(result_context, task_id) == ("RUNNING", None, None)
    assert counts(result_context) == before


def test_digest_write_failure_does_not_apply_inventory(result_context, monkeypatch):
    task_id = running_task(result_context)

    def fail_reservation(*_args, **_kwargs):
        raise sqlite3.OperationalError("injected digest write failure")

    monkeypatch.setattr(result_context["tasks"], "reserve_result_in_transaction", fail_reservation)
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 503
    assert task_state(result_context, task_id) == ("RUNNING", None, None)
    assert counts(result_context) == before


def test_begin_immediate_failure_is_retryable_and_changes_nothing(result_context, monkeypatch):
    task_id = running_task(result_context)
    real_get_connection = remote_task_api.get_connection

    class BeginFault:
        def __init__(self, connection):
            object.__setattr__(self, "_connection", connection)

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def __setattr__(self, name, value):
            setattr(self._connection, name, value)

        def execute(self, statement, *args):
            if statement == "BEGIN IMMEDIATE":
                raise sqlite3.OperationalError("database is locked")
            return self._connection.execute(statement, *args)

    monkeypatch.setattr(
        remote_task_api, "get_connection",
        lambda path: BeginFault(real_get_connection(path)),
    )
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 503
    assert task_state(result_context, task_id) == ("RUNNING", None, None)
    assert counts(result_context) == before


def test_storage_error_with_rollback_error_remains_retryable(result_context, monkeypatch):
    task_id = running_task(result_context)
    real_get_connection = remote_task_api.get_connection
    real_process = remote_task_api.DeviceInventoryService.process_scan

    class RollbackFault:
        def __init__(self, connection):
            object.__setattr__(self, "_connection", connection)

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def __setattr__(self, name, value):
            setattr(self._connection, name, value)

        def rollback(self):
            raise sqlite3.OperationalError("injected rollback failure")

    def write_then_fail(*args, **kwargs):
        real_process(*args, **kwargs)
        raise sqlite3.OperationalError("original inventory write failure")

    monkeypatch.setattr(
        remote_task_api, "get_connection",
        lambda path: RollbackFault(real_get_connection(path)),
    )
    monkeypatch.setattr(
        remote_task_api.DeviceInventoryService, "process_scan", write_then_fail
    )
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 503
    assert exc.value.detail["code"] == "RESULT_RETRYABLE"
    assert task_state(result_context, task_id) == ("RUNNING", None, None)
    assert counts(result_context) == before


def test_unexpected_fresh_commit_state_is_ambiguous_and_not_reapplied(result_context, monkeypatch):
    task_id = running_task(result_context)
    real_get_connection = remote_task_api.get_connection
    db_path = result_context["path"]

    class UnexpectedCommitState:
        def __init__(self, connection):
            object.__setattr__(self, "_connection", connection)

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def __setattr__(self, name, value):
            setattr(self._connection, name, value)

        def commit(self):
            self._connection.commit()
            with real_get_connection(db_path) as external:
                external.execute(
                    "UPDATE remote_sensor_tasks SET status='FAILED' WHERE id=?",
                    (task_id,),
                )
            raise sqlite3.OperationalError("commit response lost after state changed")

    monkeypatch.setattr(
        remote_task_api, "get_connection",
        lambda path: UnexpectedCommitState(real_get_connection(path)),
    )
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 503
    assert exc.value.detail["code"] == "RESULT_STATE_AMBIGUOUS"
    assert task_state(result_context, task_id)[0] == "FAILED"
    applied = counts(result_context)

    with pytest.raises(HTTPException) as retry:
        submit(result_context, task_id, host_body())
    assert retry.value.status_code == 409
    assert counts(result_context) == applied


def test_permanent_scope_error_fails_task_without_digest_or_inventory(result_context):
    task_id = running_task(result_context)
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body("8.8.8.8"))
    assert exc.value.status_code == 400
    assert task_state(result_context, task_id) == ("FAILED", None, "RESULT_OUTSIDE_SCOPE")
    assert counts(result_context) == before


def test_wrong_task_result_type_fails_without_reserving_digest(result_context):
    task_id = running_task(result_context, "DISCOVER_NETWORK")
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, service_body())
    assert exc.value.status_code == 400
    assert task_state(result_context, task_id) == ("FAILED", None, "INVALID_RESULT")
    assert counts(result_context) == before
    with pytest.raises(HTTPException) as retry:
        submit(result_context, task_id, service_body())
    assert retry.value.status_code == 409
    assert counts(result_context) == before


def test_legacy_running_digest_state_is_rejected_without_reapplication(result_context):
    task_id = running_task(result_context)
    with get_connection(result_context["path"]) as connection:
        connection.execute(
            "UPDATE remote_sensor_tasks SET result_digest='legacy-reservation' WHERE id=?",
            (task_id,),
        )
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 409
    assert task_state(result_context, task_id) == ("RUNNING", "legacy-reservation", None)
    assert counts(result_context) == before


@pytest.mark.parametrize(
    ("status", "digest"),
    [("FAILED", "legacy-digest"), ("COMPLETED", None)],
)
def test_terminal_or_unidentifiable_legacy_task_is_rejected(result_context, status, digest):
    task_id = running_task(result_context)
    with get_connection(result_context["path"]) as connection:
        connection.execute(
            "UPDATE remote_sensor_tasks SET status=?,result_digest=? WHERE id=?",
            (status, digest, task_id),
        )
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 409
    assert task_state(result_context, task_id) == (status, digest, None)
    assert counts(result_context) == before


def test_wrong_sensor_cannot_submit_task_result(result_context):
    task_id = running_task(result_context)
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        remote_task_api._process_task_result(
            result_context["store"], result_context["tasks"],
            result_context["sensor"]["id"] + 1, task_id, host_body(),
        )
    assert exc.value.status_code == 404
    assert task_state(result_context, task_id) == ("RUNNING", None, None)
    assert counts(result_context) == before


def test_expired_task_is_failed_without_digest_or_inventory(result_context):
    task_id = running_task(result_context)
    before = counts(result_context)
    result_context["clock"][0] = NOW.replace(minute=16)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 409
    assert task_state(result_context, task_id) == ("FAILED", None, "TASK_EXPIRED")
    assert counts(result_context) == before


def test_scope_disabled_before_result_is_revalidated_and_rejected(result_context):
    task_id = running_task(result_context)
    with get_connection(result_context["path"]) as connection:
        connection.execute(
            "UPDATE authorized_scopes SET enabled=0 WHERE id=?",
            (result_context["scope"]["id"],),
        )
    before = counts(result_context)
    with pytest.raises(HTTPException) as exc:
        submit(result_context, task_id, host_body())
    assert exc.value.status_code == 403
    assert task_state(result_context, task_id) == ("FAILED", None, "SCOPE_NOT_ASSIGNED")
    assert counts(result_context) == before


@pytest.mark.parametrize(
    ("commit_effect", "rollback_fails", "close_fails"),
    [("before", False, False), ("before", True, False),
     ("after", False, False), ("after", False, True)],
)
def test_commit_error_rereads_task_state_before_responding(
    result_context, monkeypatch, commit_effect, rollback_fails, close_fails
):
    task_id = running_task(result_context)
    real_get_connection = remote_task_api.get_connection

    class CommitFault:
        def __init__(self, connection):
            object.__setattr__(self, "_connection", connection)

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def __setattr__(self, name, value):
            setattr(self._connection, name, value)

        def commit(self):
            if commit_effect == "after":
                self._connection.commit()
            raise sqlite3.OperationalError("injected commit failure")

        def rollback(self):
            if rollback_fails:
                raise sqlite3.OperationalError("injected rollback failure")
            self._connection.rollback()

        def close(self):
            self._connection.close()
            if close_fails:
                raise sqlite3.OperationalError("injected close failure")

    monkeypatch.setattr(
        remote_task_api, "get_connection",
        lambda path: CommitFault(real_get_connection(path)),
    )
    if commit_effect == "after":
        response = submit(result_context, task_id, host_body())
        assert response["status"] == "COMPLETED"
        assert response["duplicate"] is True
        assert task_state(result_context, task_id)[0] == "COMPLETED"
    else:
        with pytest.raises(HTTPException) as exc:
            submit(result_context, task_id, host_body())
        assert exc.value.status_code == 503
        assert task_state(result_context, task_id) == ("RUNNING", None, None)
        assert counts(result_context)[1] == 0


def test_identical_concurrent_submissions_apply_once(result_context):
    task_id = running_task(result_context)
    body = host_body()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(submit, result_context, task_id, body) for _ in range(2)]
        results = [future.result() for future in futures]
    assert sum(bool(result.get("duplicate")) for result in results) == 1
    assert all(result["status"] == "COMPLETED" for result in results)
    with get_connection(result_context["path"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM device_observations").fetchone()[0] == 1


def test_different_concurrent_submissions_have_one_winner(result_context):
    task_id = running_task(result_context)
    bodies = [host_body("192.168.1.55"), host_body("192.168.1.56")]

    def attempt(body):
        try:
            return submit(result_context, task_id, body)
        except HTTPException as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(attempt, body) for body in bodies]
        outcomes = [future.result() for future in futures]
    successes = [outcome for outcome in outcomes if isinstance(outcome, dict)]
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, HTTPException)]
    assert len(successes) == len(conflicts) == 1
    assert conflicts[0].status_code == 409
    assert counts(result_context)[1] == 1
