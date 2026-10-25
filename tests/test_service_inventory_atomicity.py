import sqlite3
from datetime import datetime, timedelta

import pytest

from database.db import get_connection
from database.inventory import create_device
from database.networks import create_network
from database import services as services_db
from services import service_inventory as service_inventory_module
from services.service_inventory import ServiceInventoryService
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)


START = datetime(2026, 10, 11, 12, 0, 0)


def setup_context(db_path):
    network = create_network(
        cidr="192.168.1.0/24", name="Test LAN", description="",
        authorized=True, enabled=True, db_path=db_path,
    )
    device = create_device(
        stable_key="network:1:mac:aa:bb:cc:dd:ee:ff", network_id=network["id"],
        mac_address="aa:bb:cc:dd:ee:ff", hostname="server", vendor="Vendor",
        first_seen=START.isoformat(), last_seen=START.isoformat(),
        last_ip_address="192.168.1.20", status="ONLINE",
        identity_confidence="HIGH", db_path=db_path,
    )
    return network, device


def make_port(number, at=START):
    return PortObservation("192.168.1.20", number, "tcp", "open", at, "test")


def make_service(number, at=START, *, product="OpenSSH"):
    return ServiceObservation(
        "192.168.1.20", number, "tcp", "ssh", product, "9.6", None,
        "HIGH", at, "test",
    )


def make_result(ports, services=(), at=START):
    return ServiceDiscoveryResult(
        "192.168.1.20", "test", START, at, tuple(ports), tuple(services)
    )


def counts(db_path):
    with get_connection(db_path) as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "ports", "port_observations", "services",
                "service_observations", "changes",
            )
        }


@pytest.mark.parametrize("failure_point", ["port_create", "port_change", "port_observation"])
def test_new_port_failure_rolls_back_result(tmp_path, monkeypatch, failure_point):
    db_path = tmp_path / f"new-port-{failure_point}.db"
    network, device = setup_context(db_path)
    real_create = services_db.create_port
    real_persist = service_inventory_module.persist_changes

    if failure_point == "port_create":
        def fail_after_create(*args, **kwargs):
            real_create(*args, **kwargs)
            raise sqlite3.IntegrityError("injected after port create")
        monkeypatch.setattr(services_db, "create_port", fail_after_create)
    elif failure_point == "port_change":
        def fail_after_change(*args, **kwargs):
            real_persist(*args, **kwargs)
            raise sqlite3.IntegrityError("injected after port change")
        monkeypatch.setattr(service_inventory_module, "persist_changes", fail_after_change)
    else:
        def fail_observation(*_args, **_kwargs):
            raise sqlite3.IntegrityError("injected before port observation")
        monkeypatch.setattr(services_db, "save_port_observation", fail_observation)

    with pytest.raises(sqlite3.IntegrityError):
        ServiceInventoryService(db_path).process_result(
            network, device, make_result([make_port(22)])
        )
    assert counts(db_path) == {
        "ports": 0, "port_observations": 0, "services": 0,
        "service_observations": 0, "changes": 0,
    }


def test_existing_port_update_failure_rolls_back_state_and_history(tmp_path, monkeypatch):
    db_path = tmp_path / "existing-port.db"
    network, device = setup_context(db_path)
    service = ServiceInventoryService(db_path)
    first = service.process_result(network, device, make_result([make_port(22)]))
    before = counts(db_path)
    real_update = services_db.update_port

    def fail_after_update(*args, **kwargs):
        real_update(*args, **kwargs)
        raise sqlite3.IntegrityError("injected after port update")

    monkeypatch.setattr(services_db, "update_port", fail_after_update)
    later = START + timedelta(minutes=5)
    with pytest.raises(sqlite3.IntegrityError):
        service.process_result(network, device, make_result([make_port(22, later)], at=later))

    with get_connection(db_path) as connection:
        row = connection.execute("SELECT state, last_seen FROM ports WHERE id=?", (first["ports"][0]["id"],)).fetchone()
    assert row == ("open", START.isoformat())
    assert counts(db_path) == before


@pytest.mark.parametrize("failure_point", ["service_create", "service_observation"])
def test_new_service_failure_rolls_back_port_and_service_effects(tmp_path, monkeypatch, failure_point):
    db_path = tmp_path / f"new-service-{failure_point}.db"
    network, device = setup_context(db_path)
    real_create = services_db.create_service

    if failure_point == "service_create":
        def fail_after_create(*args, **kwargs):
            real_create(*args, **kwargs)
            raise sqlite3.IntegrityError("injected after service create")
        monkeypatch.setattr(services_db, "create_service", fail_after_create)
    else:
        def fail_observation(*_args, **_kwargs):
            raise sqlite3.IntegrityError("injected before service observation")
        monkeypatch.setattr(services_db, "save_service_observation", fail_observation)

    with pytest.raises(sqlite3.IntegrityError):
        ServiceInventoryService(db_path).process_result(
            network, device,
            make_result([make_port(22)], [make_service(22)]),
        )
    assert counts(db_path) == {
        "ports": 0, "port_observations": 0, "services": 0,
        "service_observations": 0, "changes": 0,
    }


def test_existing_service_update_failure_restores_metadata_and_history(tmp_path, monkeypatch):
    db_path = tmp_path / "existing-service.db"
    network, device = setup_context(db_path)
    service = ServiceInventoryService(db_path)
    first = service.process_result(
        network, device,
        make_result([make_port(22)], [make_service(22)]),
    )
    before = counts(db_path)
    real_update = services_db.update_service

    def fail_after_update(*args, **kwargs):
        real_update(*args, **kwargs)
        raise sqlite3.IntegrityError("injected after service update")

    monkeypatch.setattr(services_db, "update_service", fail_after_update)
    later = START + timedelta(minutes=5)
    with pytest.raises(sqlite3.IntegrityError):
        service.process_result(
            network, device,
            make_result([make_port(22, later)], [make_service(22, later, product="Changed")], at=later),
        )

    with get_connection(db_path) as connection:
        row = connection.execute(
            "SELECT product, last_seen FROM services WHERE id=?",
            (first["services"][0]["id"],),
        ).fetchone()
    assert row == ("OpenSSH", START.isoformat())
    assert counts(db_path) == before


@pytest.mark.parametrize("failure_point", ["later_port", "later_service"])
def test_later_result_failure_rolls_back_earlier_port_service_writes(tmp_path, monkeypatch, failure_point):
    db_path = tmp_path / f"later-{failure_point}.db"
    network, device = setup_context(db_path)
    real_port_observation = services_db.save_port_observation
    real_service_observation = services_db.save_service_observation
    calls = 0

    if failure_point == "later_port":
        def fail_second_port(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise sqlite3.IntegrityError("injected on second port")
            return real_port_observation(*args, **kwargs)
        monkeypatch.setattr(services_db, "save_port_observation", fail_second_port)
        result = make_result([make_port(22), make_port(80)])
    else:
        def fail_second_service(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise sqlite3.IntegrityError("injected on second service")
            return real_service_observation(*args, **kwargs)
        monkeypatch.setattr(services_db, "save_service_observation", fail_second_service)
        result = make_result(
            [make_port(22), make_port(80)], [make_service(22), make_service(80)]
        )

    with pytest.raises(sqlite3.IntegrityError):
        ServiceInventoryService(db_path).process_result(network, device, result)
    assert counts(db_path) == {
        "ports": 0, "port_observations": 0, "services": 0,
        "service_observations": 0, "changes": 0,
    }


def test_change_failure_rolls_back_port_write_across_modules(tmp_path, monkeypatch):
    db_path = tmp_path / "change-failure.db"
    network, device = setup_context(db_path)
    real_persist = service_inventory_module.persist_changes

    def fail_after_change(*args, **kwargs):
        real_persist(*args, **kwargs)
        raise sqlite3.IntegrityError("injected after change persistence")

    monkeypatch.setattr(service_inventory_module, "persist_changes", fail_after_change)
    with pytest.raises(sqlite3.IntegrityError):
        ServiceInventoryService(db_path).process_result(
            network, device, make_result([make_port(22)])
        )
    assert counts(db_path) == {
        "ports": 0, "port_observations": 0, "services": 0,
        "service_observations": 0, "changes": 0,
    }


def test_supplied_connection_result_can_be_rolled_back_by_caller(tmp_path, monkeypatch):
    db_path = tmp_path / "caller-owned.db"
    network, device = setup_context(db_path)
    connection = get_connection(db_path)
    connection.row_factory = sqlite3.Row

    def forbidden(*_args, **_kwargs):
        pytest.fail("supplied-connection result opened or initialized another connection")

    monkeypatch.setattr(service_inventory_module, "initialize_database", forbidden)
    monkeypatch.setattr(service_inventory_module, "get_connection", forbidden)
    try:
        connection.execute("BEGIN IMMEDIATE")
        ServiceInventoryService(db_path)._process_result(
            network["id"], device["id"], device["last_ip_address"],
            make_result([make_port(22)], [make_service(22)]), conn=connection,
        )
        assert connection.in_transaction
        assert connection.execute("SELECT COUNT(*) FROM ports").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 1
        connection.rollback()
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()
    assert counts(db_path) == {
        "ports": 0, "port_observations": 0, "services": 0,
        "service_observations": 0, "changes": 0,
    }


def test_standalone_result_uses_one_processing_connection_and_commits(tmp_path, monkeypatch):
    db_path = tmp_path / "successful.db"
    network, device = setup_context(db_path)
    real_init = service_inventory_module.initialize_database
    real_get = service_inventory_module.get_connection
    init_calls = connection_calls = 0

    def count_init(path):
        nonlocal init_calls
        init_calls += 1
        return real_init(path)

    def count_get(path):
        nonlocal connection_calls
        connection_calls += 1
        return real_get(path)

    monkeypatch.setattr(service_inventory_module, "initialize_database", count_init)
    monkeypatch.setattr(service_inventory_module, "get_connection", count_get)
    processed = ServiceInventoryService(db_path).process_result(
        network, device,
        make_result([make_port(i) for i in range(1, 22)],
                    [make_service(i) for i in range(1, 22)]),
    )
    assert len(processed["ports"]) == len(processed["services"]) == 21
    assert init_calls == connection_calls == 1
    monkeypatch.setattr(service_inventory_module, "initialize_database", real_init)
    monkeypatch.setattr(service_inventory_module, "get_connection", real_get)
    assert counts(db_path) == {
        "ports": 21, "port_observations": 21, "services": 21,
        "service_observations": 21, "changes": 42,
    }


def test_empty_result_preserves_no_reconciliation_behavior(tmp_path):
    db_path = tmp_path / "empty.db"
    network, device = setup_context(db_path)
    service = ServiceInventoryService(db_path)
    service.process_result(network, device, make_result([make_port(22)]))
    result = service.process_result(network, device, make_result([]))
    assert result == {"ports": [], "services": []}
    assert counts(db_path)["ports"] == 1
    assert counts(db_path)["port_observations"] == 1
