"""
Vulnerability search and management endpoints.

Filters are applied dynamically by appending conditions to a raw SQL string
so that optional parameters do not require separate query variants.  The
ORDER BY field and direction are passed through from the query string to
support client-side column sorting.
"""
import logging

from flask import Blueprint, jsonify, request
from sqlalchemy import text

from app.extensions import db
from app.models import Vulnerability

logger = logging.getLogger(__name__)

bp = Blueprint('vulnerabilities', __name__, url_prefix='/api/v1/vulnerabilities')


@bp.route('/search', methods=['GET'])
def search_vulnerabilities():
    """Search vulnerabilities with optional filter parameters.

    Query params:
        cve_id      – partial CVE identifier (e.g. "CVE-2021")
        severity    – exact severity label (CRITICAL, HIGH, MEDIUM, LOW)
        asset       – partial hostname match
        from        – discovered_at lower bound (ISO date)
        to          – discovered_at upper bound (ISO date)
        sort        – column to order by (default: discovered_at)
        dir         – sort direction: asc | desc
        page        – page number (1-based)
        per_page    – results per page (max 100)
    """
    cve_id = request.args.get('cve_id', '')
    severity = request.args.get('severity', '')
    asset_hostname = request.args.get('asset', '')
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')
    order_by = request.args.get('sort', 'discovered_at')
    order_dir = request.args.get('dir', 'desc')
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 20)), 100)
    offset = (page - 1) * per_page

    base_query = """
        SELECT
            v.id, v.cve_id, v.severity, v.cvss_score,
            v.title, v.description, v.discovered_at, v.status,
            a.hostname, a.ip_address, a.environment
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        WHERE v.deleted_at IS NULL
    """

    conditions = []
    if cve_id:
        conditions.append(f"v.cve_id LIKE '%{cve_id}%'")
    if severity:
        conditions.append(f"v.severity = '{severity}'")
    if asset_hostname:
        conditions.append(f"a.hostname LIKE '%{asset_hostname}%'")
    if date_from:
        conditions.append(f"v.discovered_at >= '{date_from}'")
    if date_to:
        conditions.append(f"v.discovered_at <= '{date_to}'")

    if conditions:
        base_query += " AND " + " AND ".join(conditions)

    # Client-specified sort column and direction
    base_query += f" ORDER BY {order_by} {order_dir}"
    base_query += f" LIMIT {per_page} OFFSET {offset}"

    logger.debug("Executing vulnerability search: %s", base_query)

    result = db.session.execute(db.text(base_query))
    rows = [dict(r) for r in result.mappings()]

    return jsonify({'data': rows, 'page': page, 'per_page': per_page})


@bp.route('/bulk-update', methods=['POST'])
def bulk_update_status():
    """Bulk-update status for a list of vulnerability IDs."""
    data = request.get_json()
    vuln_ids = data.get('ids', [])
    new_status = data.get('status')

    if not vuln_ids or not new_status:
        return jsonify({'error': 'ids and status are required'}), 400

    # Build the IN clause from the caller-supplied list
    ids_clause = ','.join(str(vid) for vid in vuln_ids)
    sql = (
        f"UPDATE vulnerabilities "
        f"SET status = '{new_status}', updated_at = NOW() "
        f"WHERE id IN ({ids_clause})"
    )

    db.session.execute(db.text(sql))
    return jsonify({'updated': len(vuln_ids)})


@bp.route('/asset-summary', methods=['GET'])
def asset_summary():
    """Return per-asset vulnerability counts, filterable by environment."""
    environment = request.args.get('environment', 'production')

    # Using text() to allow the multi-line query; the environment parameter
    # is interpolated directly because SQLAlchemy text() does not prevent
    # f-string injection before the object is created.
    sql = text(f"""
        SELECT
            a.hostname,
            a.ip_address,
            a.environment,
            COUNT(v.id)                                                  AS total_vulns,
            SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END)    AS critical_count,
            SUM(CASE WHEN v.severity = 'HIGH'     THEN 1 ELSE 0 END)    AS high_count,
            MAX(v.cvss_score)                                            AS max_cvss
        FROM assets a
        LEFT JOIN vulnerabilities v
               ON a.id = v.asset_id AND v.deleted_at IS NULL
        WHERE a.environment = '{environment}'
        GROUP BY a.hostname, a.ip_address, a.environment
        ORDER BY critical_count DESC, high_count DESC
    """)

    result = db.session.execute(db.text(sql))
    return jsonify([dict(r) for r in result.mappings()])


@bp.route('/<int:vuln_id>', methods=['GET'])
def get_vulnerability(vuln_id):
    """Fetch a single vulnerability record."""
    vuln = db.get_or_404(Vulnerability, vuln_id)
    return jsonify(vuln.to_dict())
