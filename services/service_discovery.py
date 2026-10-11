import ipaddress
from collections.abc import Mapping

from services.scan_models import ScanModelError, normalize_ipv4
from services.scanner import ServiceDiscoveryScanner
from services.service_models import ServiceDiscoveryResult
from services.target_policy import validate_cidr


class ServiceDiscoveryError(ValueError):
    """Raised when service discovery cannot use the requested device."""


def discover_services(
    network: Mapping[str, object],
    device: Mapping[str, object],
    scanner: ServiceDiscoveryScanner,
) -> ServiceDiscoveryResult:
    if not isinstance(network, Mapping) or not isinstance(device, Mapping):
        raise ServiceDiscoveryError("Stored network and device records are required.")

    if network.get("authorized") is not True:
        raise ServiceDiscoveryError("The network is not authorized.")

    if network.get("enabled") is not True:
        raise ServiceDiscoveryError("The network is disabled.")

    if network.get("id") != device.get("network_id"):
        raise ServiceDiscoveryError("The device does not belong to the network.")

    cidr = network.get("cidr")
    target_ip = device.get("last_ip_address")

    if not isinstance(cidr, str) or not isinstance(target_ip, str):
        raise ServiceDiscoveryError("Network and device targets are invalid.")

    try:
        normalized_cidr = validate_cidr(cidr).cidr
        normalized_ip = normalize_ipv4(target_ip)
    except ScanModelError as exc:
        raise ServiceDiscoveryError("Device target must be valid IPv4.") from exc

    if ipaddress.ip_address(normalized_ip) not in ipaddress.ip_network(
        normalized_cidr
    ):
        raise ServiceDiscoveryError("Device target is outside its network.")

    result = scanner.discover_services(normalized_ip)

    if not isinstance(result, ServiceDiscoveryResult):
        raise ServiceDiscoveryError("Scanner returned an invalid service result.")

    if result.target_ip != normalized_ip:
        raise ServiceDiscoveryError(
            "Scanner result target does not match the device."
        )

    return result