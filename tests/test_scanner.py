"""Tests for the Nmap scanner service."""
import pytest
from unittest.mock import patch, MagicMock

from app.services.scanner_service import run_nmap_scan, check_service_banner


def test_run_nmap_scan_basic():
    """run_nmap_scan builds the expected command string."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "<nmaprun/>"
    mock_result.stderr = ""

    with patch('subprocess.run', return_value=mock_result) as mock_run:
        result = run_nmap_scan('192.168.1.1', scan_type='basic')

    assert result['returncode'] == 0
    call_args = mock_run.call_args
    cmd = call_args[0][0]
    assert '192.168.1.1' in cmd
    assert '-sV' in cmd


def test_run_nmap_scan_with_ports():
    """Port range is included when provided."""
    mock_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch('subprocess.run', return_value=mock_result) as mock_run:
        run_nmap_scan('10.0.0.1', ports='22,80,443')

    cmd = mock_run.call_args[0][0]
    assert '-p 22,80,443' in cmd


def test_run_nmap_scan_custom_args_passed_through():
    """Custom args are appended without filtering."""
    mock_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch('subprocess.run', return_value=mock_result) as mock_run:
        run_nmap_scan('10.0.0.1', custom_args='--script-args http.useragent=test')

    cmd = mock_run.call_args[0][0]
    assert '--script-args' in cmd


def test_check_service_banner_ssh():
    """SSH banner check uses ssh-keyscan."""
    mock_result = MagicMock(returncode=0, stdout="ssh-rsa AAAAB...", stderr="")
    with patch('subprocess.run', return_value=mock_result) as mock_run:
        output = check_service_banner('myhost', 22, 'ssh')

    cmd = mock_run.call_args[0][0]
    assert 'ssh-keyscan' in cmd
    assert 'myhost' in cmd
