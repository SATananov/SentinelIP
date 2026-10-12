import ipaddress
import re


class HostnamePolicyError(ValueError):
    """Raised when input is not a canonicalizable DNS hostname."""


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)


def normalize_hostname(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise HostnamePolicyError("A DNS hostname is required.")
    value = value.strip()
    if not value or any(character.isspace() for character in value):
        raise HostnamePolicyError("Hostname contains whitespace or is empty.")
    if any(character in value for character in ":/@?#\\%") or "://" in value:
        raise HostnamePolicyError("Enter a hostname without a URL, path, or port.")

    hostname = value[:-1] if value.endswith(".") else value
    if not hostname or hostname.endswith("."):
        raise HostnamePolicyError("Hostname contains an empty label.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise HostnamePolicyError("IP literals are not accepted as hostnames.")

    labels = hostname.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise HostnamePolicyError("Enter a fully qualified DNS hostname.")
    if len(labels) == 4 and all(label.isascii() and label.isdigit() for label in labels):
        raise HostnamePolicyError("IP literals are not accepted as hostnames.")
    normalized_labels = []
    for label in labels:
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise HostnamePolicyError("Hostname contains an invalid IDNA label.") from exc
        if len(ascii_label) > 63 or not _LABEL.fullmatch(ascii_label):
            raise HostnamePolicyError("Hostname contains an invalid DNS label.")
        if ascii_label.startswith("xn--"):
            try:
                if ascii_label.encode("ascii").decode("idna").encode("idna").decode("ascii").lower() != ascii_label:
                    raise UnicodeError
            except UnicodeError as exc:
                raise HostnamePolicyError("Hostname contains an invalid IDNA label.") from exc
        normalized_labels.append(ascii_label)

    canonical = ".".join(normalized_labels)
    if len(canonical.encode("ascii")) > 253:
        raise HostnamePolicyError("Hostname exceeds the DNS name length limit.")
    return canonical
