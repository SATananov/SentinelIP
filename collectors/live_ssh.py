import subprocess
from collections.abc import Iterator

DEFAULT_HOST = "192.168.122.25"
DEFAULT_USER = "tanashi"
DEFAULT_KEY = "/home/tanashi/.ssh/sentinelip_ed25519"


def stream_ssh_logs(
    host: str = DEFAULT_HOST,
    user: str = DEFAULT_USER,
    key_path: str = DEFAULT_KEY,
) -> Iterator[str]:
    command = [
        "ssh",
        "-i",
        key_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        f"{user}@{host}",
        "journalctl",
        "-u",
        "ssh",
        "-f",
        "-n",
        "0",
        "--no-pager",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    if process.stdout is None:
        raise RuntimeError("Unable to read SSH log stream.")

    try:
        for line in process.stdout:
            yield line.rstrip()
    finally:
        process.terminate()
