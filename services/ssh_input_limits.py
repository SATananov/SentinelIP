"""Shared resource limits for the legacy SSH event ingestion path."""

MAX_SSH_LOG_LINE_BYTES = 8192
MAX_SSH_USERNAME_BYTES = 256


class SSHUsernameValidationError(ValueError):
    """A username cannot be stored within the SSH ingestion contract."""

    def __init__(self):
        super().__init__("SSH username exceeds the configured byte limit.")


def validate_ssh_username(username: str | None) -> None:
    if username is None or not isinstance(username, str):
        return

    try:
        size = len(username.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise SSHUsernameValidationError() from None

    if size > MAX_SSH_USERNAME_BYTES:
        raise SSHUsernameValidationError()
