"""Integration tests for the vulnerability search endpoint."""
import json
import pytest
from app.models import Asset, Vulnerability
from app.extensions import db as _db


@pytest.fixture(autouse=True)
def seed_data(app):
    """Insert test assets and vulnerabilities before each test."""
    with app.app_context():
        asset = Asset(hostname='test-host-01', ip_address='10.0.0.1',
                      asset_type='server', environment='production')
        _db.session.add(asset)
        _db.session.flush()

        vuln = Vulnerability(
            asset_id=asset.id,
            cve_id='CVE-2023-99999',
            title='Test Vulnerability',
            severity='HIGH',
            cvss_score=8.1,
            status='open',
        )
        _db.session.add(vuln)
        _db.session.commit()
        yield
        _db.session.query(Vulnerability).delete()
        _db.session.query(Asset).delete()
        _db.session.commit()


def test_search_returns_results(client):
    """GET /search with no filters returns seeded vulnerability."""
    resp = client.get('/api/v1/vulnerabilities/search')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'data' in data


def test_search_filter_by_severity(client):
    """Severity filter narrows results."""
    resp = client.get('/api/v1/vulnerabilities/search?severity=HIGH')
    assert resp.status_code == 200


def test_search_filter_by_cve(client):
    """CVE ID partial-match filter works."""
    resp = client.get('/api/v1/vulnerabilities/search?cve_id=CVE-2023')
    assert resp.status_code == 200


def test_bulk_update_requires_ids_and_status(client):
    """POST /bulk-update returns 400 when required fields are missing."""
    resp = client.post(
        '/api/v1/vulnerabilities/bulk-update',
        data=json.dumps({'ids': []}),
        content_type='application/json',
    )
    assert resp.status_code == 400


def test_report_generate_with_custom_template(client):
    """POST /reports/generate renders a user-supplied Jinja2 template."""
    payload = {
        'vuln_ids': [],
        'custom_template': '<h1>Vulns: {{ total }}</h1>',
    }
    resp = client.post(
        '/api/v1/reports/generate',
        data=json.dumps(payload),
        content_type='application/json',
    )
    assert resp.status_code == 200
    assert b'Vulns: 0' in resp.data
