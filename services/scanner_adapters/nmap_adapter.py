import subprocess
import xml.etree.ElementTree as ElementTree
from datetime import datetime

from services.scan_models import (
    HostDiscoveryResult,
    ScanModelError,
    ScanResult,
    normalize_ipv4,
)
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)
from services.target_policy import validate_cidr
from services.public_target_policy import normalize_public_ipv4


class ScannerUnavailableError(RuntimeError):
    """Raised when the configured scanner executable is unavailable."""


class ScannerTimeoutError(RuntimeError):
    """Raised when scanner execution exceeds its fixed timeout."""


class ScannerExecutionError(RuntimeError):
    """Raised when the scanner exits unsuccessfully."""


class ScannerParseError(RuntimeError):
    """Raised when scanner XML cannot be normalized safely."""


CONSERVATIVE_TCP_PORTS = (
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    587,
    993,
    995,
    1433,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
)


def _check_output_size(stdout: str, stderr: str, max_output_bytes: int):
    stdout_size = len(stdout.encode("utf-8")) if stdout else 0
    stderr_size = len(stderr.encode("utf-8")) if stderr else 0

    if stdout_size + stderr_size > max_output_bytes:
        raise ScannerExecutionError("Nmap output exceeded the size limit.")


def _service_confidence(
    service_name: str | None,
    product: str | None,
    version: str | None,
    extra_info: str | None,
) -> str:
    if product is not None and version is not None:
        return "HIGH"

    if any(value is not None for value in (service_name, product, version, extra_info)):
        if service_name is not None and product is None and version is None:
            return "LOW"

        return "MEDIUM"

    return "LOW"


class NmapHostDiscoveryScanner:
    def __init__(
        self,
        executable: str = "nmap",
        timeout_seconds: int = 30,
        max_output_bytes: int = 1_048_576,
    ):
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def discover_hosts(self, network_cidr: str) -> ScanResult:
        validated_network = validate_cidr(network_cidr)
        return self._discover_target(validated_network.cidr, resolve_names=True)

    def discover_public_host(self, target: str) -> ScanResult:
        """Run the existing bounded -sn discovery against one approved IPv4."""
        normalized_target = normalize_public_ipv4(target)
        result = self._discover_target(normalized_target, resolve_names=False)
        if any(host.ip_address != normalized_target for host in result.hosts):
            raise ScannerParseError(
                "Nmap returned a host outside the authorized public target."
            )
        return result

    def _discover_target(self, normalized_target: str, *, resolve_names: bool) -> ScanResult:
        started_at = datetime.now()
        name_resolution_args = [] if resolve_names else ["-n"]
        command = [
            self.executable,
            "-sn",
            *name_resolution_args,
            normalized_target,
            "-oX",
            "-",
        ]

        try:
            completed = subprocess.run(
                command,
                shell=False,
                timeout=self.timeout_seconds,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ScannerUnavailableError(
                "Nmap executable is not available."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                "Nmap host discovery timed out."
            ) from exc
        except OSError as exc:
            raise ScannerExecutionError(
                "Nmap host discovery could not be started."
            ) from exc

        self._check_output_size(completed.stdout, completed.stderr)

        if completed.returncode != 0:
            raise ScannerExecutionError(
                f"Nmap host discovery failed with exit code {completed.returncode}."
            )

        completed_at = datetime.now()
        hosts = self._parse_hosts(completed.stdout, completed_at)

        return ScanResult(
            target_network=normalized_target,
            scanner="nmap",
            started_at=started_at,
            completed_at=completed_at,
            hosts=tuple(hosts),
        )

    def _check_output_size(self, stdout: str, stderr: str):
        stdout_size = len(stdout.encode("utf-8")) if stdout else 0
        stderr_size = len(stderr.encode("utf-8")) if stderr else 0

        if stdout_size + stderr_size > self.max_output_bytes:
            raise ScannerExecutionError("Nmap output exceeded the size limit.")

    def _parse_hosts(
        self,
        xml_output: str,
        discovered_at: datetime,
    ) -> list[HostDiscoveryResult]:
        try:
            root = ElementTree.fromstring(xml_output.lstrip())
        except (ElementTree.ParseError, TypeError) as exc:
            raise ScannerParseError("Nmap returned malformed XML.") from exc

        hosts = []

        for host_element in root.findall("host"):
            status_element = host_element.find("status")

            if status_element is None or status_element.get("state") != "up":
                continue

            ipv4_address = None
            mac_address = None
            vendor = None

            for address_element in host_element.findall("address"):
                address_type = address_element.get("addrtype")

                if address_type == "ipv4":
                    ipv4_address = address_element.get("addr")

                if address_type == "mac":
                    mac_address = address_element.get("addr")
                    vendor = address_element.get("vendor")

            if ipv4_address is None:
                continue

            hostname = None
            hostnames_element = host_element.find("hostnames")

            if hostnames_element is not None:
                hostname_element = hostnames_element.find("hostname")

                if hostname_element is not None:
                    hostname = hostname_element.get("name")

            try:
                hosts.append(
                    HostDiscoveryResult(
                        ip_address=ipv4_address,
                        mac_address=mac_address,
                        hostname=hostname,
                        vendor=vendor,
                        discovered_at=discovered_at,
                        source="nmap",
                    )
                )
            except ScanModelError as exc:
                raise ScannerParseError(
                    "Nmap returned invalid host evidence."
                ) from exc

        return hosts


class NmapServiceDiscoveryScanner:
    """Conservative single-device TCP port and service discovery."""

    def __init__(
        self,
        executable: str = "nmap",
        timeout_seconds: int = 45,
        max_output_bytes: int = 1_048_576,
    ):
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def discover_services(self, ip_address: str) -> ServiceDiscoveryResult:
        normalized_ip = self._validate_target(ip_address)
        return self._discover_target_services(normalized_ip, resolve_names=True)

    def discover_public_services(self, ip_address: str) -> ServiceDiscoveryResult:
        """Use the same conservative TCP profile for one authorized public IPv4."""
        return self._discover_target_services(
            normalize_public_ipv4(ip_address), resolve_names=False
        )

    def _discover_target_services(
        self, normalized_ip: str, *, resolve_names: bool
    ) -> ServiceDiscoveryResult:
        started_at = datetime.now()
        name_resolution_args = [] if resolve_names else ["-n"]
        port_list = ",".join(str(port) for port in CONSERVATIVE_TCP_PORTS)
        command = [
            self.executable,
            *name_resolution_args,
            "-sT",
            "-sV",
            "--version-light",
            "--open",
            "-p",
            port_list,
            "--max-retries",
            "2",
            "--host-timeout",
            "30s",
            "-oX",
            "-",
            normalized_ip,
        ]

        try:
            completed = subprocess.run(
                command,
                shell=False,
                timeout=self.timeout_seconds,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ScannerUnavailableError(
                "Nmap executable is not available."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                "Nmap service discovery timed out."
            ) from exc
        except OSError as exc:
            raise ScannerExecutionError(
                "Nmap service discovery could not be started."
            ) from exc

        _check_output_size(
            completed.stdout,
            completed.stderr,
            self.max_output_bytes,
        )

        if completed.returncode != 0:
            raise ScannerExecutionError(
                f"Nmap service discovery failed with exit code {completed.returncode}."
            )

        completed_at = datetime.now()
        ports, services = self._parse_services(
            completed.stdout,
            normalized_ip,
            completed_at,
        )

        return ServiceDiscoveryResult(
            target_ip=normalized_ip,
            scanner="nmap",
            started_at=started_at,
            completed_at=completed_at,
            ports=tuple(ports),
            services=tuple(services),
        )

    @staticmethod
    def _validate_target(ip_address: str) -> str:
        try:
            normalized_ip = normalize_ipv4(ip_address)
        except ScanModelError as exc:
            raise ScannerParseError(
                "Nmap service discovery requires one valid IPv4 target."
            ) from exc

        import ipaddress

        address = ipaddress.ip_address(normalized_ip)

        if not address.is_private:
            raise ScannerParseError(
                "Nmap service discovery requires a private IPv4 target."
            )

        return normalized_ip

    def _parse_services(
        self,
        xml_output: str,
        target_ip: str,
        observed_at: datetime,
    ) -> tuple[list[PortObservation], list[ServiceObservation]]:
        if not isinstance(xml_output, str):
            raise ScannerParseError("Nmap returned invalid XML output.")

        try:
            root = ElementTree.fromstring(xml_output.lstrip())
        except ElementTree.ParseError as exc:
            raise ScannerParseError("Nmap returned malformed XML.") from exc

        ports = []
        services = []

        for host_element in root.findall("host"):
            host_address = None

            for address_element in host_element.findall("address"):
                if address_element.get("addrtype") == "ipv4":
                    host_address = address_element.get("addr")
                    break

            if host_address is not None:
                try:
                    normalized_host_address = normalize_ipv4(host_address)
                except ScanModelError as exc:
                    raise ScannerParseError(
                        "Nmap returned an invalid IPv4 target."
                    ) from exc

                if normalized_host_address != target_ip:
                    raise ScannerParseError(
                        "Nmap XML target does not match the requested device."
                    )

            status_element = host_element.find("status")

            if (
                status_element is not None
                and status_element.get("state") != "up"
            ):
                continue

            ports_element = host_element.find("ports")

            if ports_element is None:
                continue

            for port_element in ports_element.findall("port"):
                if port_element.get("protocol") != "tcp":
                    continue

                state_element = port_element.find("state")

                if (
                    state_element is None
                    or state_element.get("state") != "open"
                ):
                    continue

                port_value = port_element.get("portid")

                try:
                    port_number = int(port_value)
                    port = PortObservation(
                        ip_address=target_ip,
                        port=port_number,
                        transport="tcp",
                        state="open",
                        observed_at=observed_at,
                        source="nmap",
                    )
                except (TypeError, ValueError, ScanModelError) as exc:
                    raise ScannerParseError(
                        "Nmap returned invalid port evidence."
                    ) from exc

                ports.append(port)
                service_element = port_element.find("service")

                if service_element is None:
                    continue

                service_name = service_element.get("name")
                product = service_element.get("product")
                version = service_element.get("version")
                extra_info = service_element.get("extrainfo")

                if not any(
                    value is not None
                    for value in (service_name, product, version, extra_info)
                ):
                    continue

                service = ServiceObservation(
                    ip_address=target_ip,
                    port=port.port,
                    transport="tcp",
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                    confidence=_service_confidence(
                        service_name,
                        product,
                        version,
                        extra_info,
                    ),
                    observed_at=observed_at,
                    source="nmap",
                )
                services.append(service)

        return ports, services
