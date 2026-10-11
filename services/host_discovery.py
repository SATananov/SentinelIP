from collections.abc import Mapping

from services.scan_models import ScanResult
from services.scanner import HostDiscoveryScanner
from services.target_policy import TargetPolicyError, validate_cidr


class HostDiscoveryError(ValueError):
    """Raised when host discovery cannot use the requested network target."""


def discover_hosts(
    network: Mapping[str, object],
    scanner: HostDiscoveryScanner,
) -> ScanResult:
    if not isinstance(network, Mapping):
        raise HostDiscoveryError("An authorized network record is required.")

    if network.get("authorized") is not True:
        raise HostDiscoveryError("The network is not authorized for discovery.")

    if network.get("enabled") is not True:
        raise HostDiscoveryError("The network is disabled for discovery.")

    cidr = network.get("cidr")

    if not isinstance(cidr, str):
        raise TargetPolicyError("Network record must contain a valid CIDR.")

    validated_network = validate_cidr(cidr)
    result = scanner.discover_hosts(validated_network.cidr)

    if not isinstance(result, ScanResult):
        raise HostDiscoveryError("Scanner returned an invalid scan result.")

    if result.target_network != validated_network.cidr:
        raise HostDiscoveryError(
            "Scanner result target does not match the requested network."
        )

    return result