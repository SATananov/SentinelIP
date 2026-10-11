import subprocess
import xml.etree.ElementTree as ElementTree
from datetime import datetime

from services.scan_models import (
    HostDiscoveryResult,
    ScanModelError,
    ScanResult,
)
from services.target_policy import validate_cidr


class ScannerUnavailableError(RuntimeError):
    """Raised when the configured scanner executable is unavailable."""


class ScannerTimeoutError(RuntimeError):
    """Raised when scanner execution exceeds its fixed timeout."""


class ScannerExecutionError(RuntimeError):
    """Raised when the scanner exits unsuccessfully."""


class ScannerParseError(RuntimeError):
    """Raised when scanner XML cannot be normalized safely."""


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
        normalized_cidr = validated_network.cidr
        started_at = datetime.now()
        command = [
            self.executable,
            "-sn",
            normalized_cidr,
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
            target_network=normalized_cidr,
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