import queue
import socket
import threading
from dataclasses import dataclass

from services.hostname_policy import normalize_hostname
from services.public_target_policy import (
    PublicTargetPolicyError,
    normalize_public_ipv4,
)


RESOLUTION_VERSION = "hostname-a-resolution-v1"
MAX_RESOLVED_ADDRESSES = 16
_RESOLUTION_SLOTS = threading.BoundedSemaphore(4)


class HostnameResolutionError(RuntimeError):
    """Raised when a bounded system DNS resolution cannot be completed."""


class IneligibleHostnameResolution(HostnameResolutionError):
    """Raised when the DNS result cannot be safely authorized as public IPv4."""


@dataclass(frozen=True)
class HostnameResolution:
    canonical_hostname: str
    resolved_ipv4: tuple[str, ...]
    resolution_version: str = RESOLUTION_VERSION


def _system_lookup(hostname: str) -> list[str]:
    results = socket.getaddrinfo(
        hostname,
        None,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    )
    return [item[4][0] for item in results]


class HostnameResolver:
    """Bounded A-only resolver using the host's configured DNS resolution."""

    def __init__(self, lookup=_system_lookup, timeout_seconds=3, max_addresses=MAX_RESOLVED_ADDRESSES):
        if not callable(lookup):
            raise ValueError("A DNS lookup function is required.")
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("Resolver timeout must be positive.")
        if type(max_addresses) is not int or not 1 <= max_addresses <= MAX_RESOLVED_ADDRESSES:
            raise ValueError("Resolver address limit is invalid.")
        self.lookup = lookup
        self.timeout_seconds = timeout_seconds
        self.max_addresses = max_addresses

    def resolve(self, hostname: str) -> HostnameResolution:
        canonical = normalize_hostname(hostname)
        if not _RESOLUTION_SLOTS.acquire(timeout=0.1):
            raise HostnameResolutionError("DNS resolver capacity is temporarily unavailable.")
        result_queue = queue.Queue(maxsize=1)

        def run_lookup():
            try:
                result_queue.put((True, self.lookup(canonical)))
            except BaseException as exc:  # propagate the worker error to the caller
                result_queue.put((False, exc))
            finally:
                _RESOLUTION_SLOTS.release()

        threading.Thread(target=run_lookup, name="sentinelip-hostname-resolver", daemon=True).start()
        try:
            succeeded, value = result_queue.get(timeout=self.timeout_seconds)
        except queue.Empty as exc:
            raise HostnameResolutionError("DNS resolution timed out.") from exc
        if not succeeded:
            raise HostnameResolutionError("DNS resolution failed.") from value

        try:
            addresses = tuple(sorted({normalize_public_ipv4(item) for item in value}))
        except (PublicTargetPolicyError, TypeError) as exc:
            raise IneligibleHostnameResolution(
                "Hostname resolves to an address outside the public IPv4 policy."
            ) from exc
        if not addresses:
            raise IneligibleHostnameResolution("Hostname has no IPv4 A records.")
        if len(addresses) > self.max_addresses:
            raise IneligibleHostnameResolution("Hostname resolves to too many IPv4 addresses.")
        return HostnameResolution(canonical, addresses)


def preview_hostname(hostname: str, resolver: HostnameResolver) -> dict:
    canonical = normalize_hostname(hostname)
    try:
        result = resolver.resolve(canonical)
    except IneligibleHostnameResolution as exc:
        return {
            "canonical_hostname": canonical,
            "resolved_ipv4": [],
            "eligible": False,
            "warnings": [],
            "errors": [str(exc)],
            "resolution_version": RESOLUTION_VERSION,
        }
    except HostnameResolutionError as exc:
        return {
            "canonical_hostname": canonical,
            "resolved_ipv4": [],
            "eligible": False,
            "warnings": [],
            "errors": [str(exc)],
            "resolution_version": RESOLUTION_VERSION,
        }
    return {
        "canonical_hostname": result.canonical_hostname,
        "resolved_ipv4": list(result.resolved_ipv4),
        "eligible": True,
        "warnings": [],
        "errors": [],
        "resolution_version": result.resolution_version,
    }
