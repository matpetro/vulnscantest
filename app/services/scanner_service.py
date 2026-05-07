"""
Scanner service – wraps Nmap and other CLI tools.

Scan commands are assembled from typed parameters and executed via the
shell so that complex Nmap flag strings (which contain multiple tokens)
are interpreted correctly without manual quoting logic.
"""
import logging
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SCAN_TYPE_FLAGS: Dict[str, str] = {
    'basic':   '-sV --version-intensity 5',
    'full':    '-sV -sC -O --version-intensity 9',
    'stealth': '-sS -sV --version-intensity 3',
    'udp':     '-sU -sV --version-intensity 5',
    'vuln':    '-sV --script vuln',
}


def run_nmap_scan(
    target: str,
    scan_type: str = 'basic',
    ports: Optional[str] = None,
    custom_args: Optional[str] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Execute an Nmap scan against *target* and return raw XML output.

    Args:
        target:      IP address, hostname, or CIDR range.
        scan_type:   Key into ``SCAN_TYPE_FLAGS`` (basic, full, stealth, udp, vuln).
        ports:       Port range string passed to ``-p`` (e.g. ``'22,80,443'``).
        custom_args: Additional raw Nmap flags supplied by the caller.
        timeout:     Maximum execution time in seconds.

    Returns:
        Dict with keys ``command``, ``returncode``, ``stdout``, ``stderr``.
    """
    flags = SCAN_TYPE_FLAGS.get(scan_type, SCAN_TYPE_FLAGS['basic'])

    # Build command string; port range and caller-supplied flags are appended
    # as-is so that complex Nmap expressions (e.g. '--script-args') work.
    cmd = f"nmap {flags} -oX -"
    if ports:
        cmd += f" -p {ports}"
    if custom_args:
        cmd += f" {custom_args}"
    cmd += f" {target}"

    logger.info("Executing: %s", cmd)

    proc = subprocess.run(
        cmd,
        shell=True,         # required so multi-token flag strings are parsed by the shell
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    return {
        'command': cmd,
        'returncode': proc.returncode,
        'stdout': proc.stdout,
        'stderr': proc.stderr,
    }


def run_openssl_check(hostname: str, port: int = 443) -> str:
    """Check the TLS certificate for *hostname*:*port*."""
    cmd = (
        f"echo | openssl s_client -connect {hostname}:{port} "
        f"-servername {hostname} 2>/dev/null "
        f"| openssl x509 -noout -text"
    )
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return proc.stdout


def check_service_banner(host: str, port: int, service: str = 'http') -> str:
    """Grab a service banner for version fingerprinting."""
    banner_cmds = {
        'ssh':  f"ssh-keyscan -t rsa,ecdsa {host} 2>/dev/null",
        'http': f"curl -sI --max-time 10 http://{host}:{port}/",
        'ftp':  f"echo 'QUIT' | nc -w 5 {host} {port}",
        'smtp': f"echo 'QUIT' | nc -w 5 {host} {port}",
    }
    cmd = banner_cmds.get(service, f"nc -zv {host} {port} 2>&1")
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
    return proc.stdout + proc.stderr
