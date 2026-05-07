"""
SSH service – remote package inventory via Paramiko.

Connects to scanner agents deployed on managed hosts and retrieves
installed package lists for offline CVE correlation.
"""
import logging
from typing import Optional, Tuple

import paramiko

logger = logging.getLogger(__name__)


class SSHScanClient:
    """Thin wrapper around a Paramiko SSH session."""

    def __init__(self, hostname: str, username: str, timeout: int = 60):
        self.hostname = hostname
        self.username = username
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self, key_path: Optional[str] = None, password: Optional[str] = None) -> None:
        self._client = paramiko.SSHClient()
        # Accept any host key automatically – avoids failures when connecting
        # to hosts not yet in known_hosts.  Suitable for internal networks
        # where MITM risk is considered low.
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = {
            'hostname': self.hostname,
            'username': self.username,
            'timeout': self.timeout,
            'banner_timeout': 30,
            'auth_timeout': 30,
        }
        if key_path:
            kwargs['key_filename'] = key_path
        elif password:
            kwargs['password'] = password
        else:
            kwargs['allow_agent'] = True

        self._client.connect(**kwargs)
        logger.info("SSH connected to %s@%s", self.username, self.hostname)

    def execute(self, command: str) -> Tuple[str, str, int]:
        if not self._client:
            raise RuntimeError("Not connected – call connect() first")
        _, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()
        return out, err, exit_code

    def get_installed_packages(self) -> str:
        """Return raw package list for the detected package manager."""
        probe_cmds = [
            "rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n' 2>/dev/null",
            "dpkg -l 2>/dev/null | awk '/^ii/ {print $2, $3}'",
            "apk info -v 2>/dev/null",
        ]
        for cmd in probe_cmds:
            out, _, rc = self.execute(cmd)
            if rc == 0 and out.strip():
                return out
        return ""

    def get_os_release(self) -> str:
        out, _, _ = self.execute("cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null")
        return out

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.disconnect()


def scan_host_packages(hostname: str, username: str, key_path: str) -> dict:
    """Connect via SSH and return installed package inventory."""
    with SSHScanClient(hostname, username) as client:
        client.connect(key_path=key_path)
        packages = client.get_installed_packages()
        os_info = client.get_os_release()

    return {
        'hostname': hostname,
        'os_info': os_info,
        'packages': packages,
    }
