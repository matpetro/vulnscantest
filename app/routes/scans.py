"""Scan management endpoints."""
import uuid
import logging

from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models import ScanJob
from app.services.scanner_service import run_nmap_scan

logger = logging.getLogger(__name__)

bp = Blueprint('scans', __name__, url_prefix='/api/v1/scans')


@bp.route('', methods=['POST'])
def create_scan():
    """Submit a new scan job."""
    body = request.get_json(force=True)
    target = body.get('target')
    if not target:
        return jsonify({'error': 'target is required'}), 400

    scan_id = str(uuid.uuid4())
    job = ScanJob(
        id=scan_id,
        target=target,
        scan_type=body.get('scan_type', 'basic'),
        ports=body.get('ports'),
        status='pending',
    )
    db.session.add(job)
    db.session.commit()

    # For simplicity, run synchronously; a Celery task queue is planned.
    try:
        result = run_nmap_scan(
            target=target,
            scan_type=body.get('scan_type', 'basic'),
            ports=body.get('ports'),
            custom_args=body.get('nmap_args'),
        )
        job.status = 'completed' if result['returncode'] == 0 else 'failed'
        job.error_message = result.get('stderr') or None
    except Exception as exc:
        logger.exception("Scan job %s failed", scan_id)
        job.status = 'failed'
        job.error_message = str(exc)

    db.session.commit()
    return jsonify({'scan_id': scan_id, 'status': job.status}), 202


@bp.route('/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Retrieve scan job status and result."""
    from app.utils.cache import get_scan_result

    job = ScanJob.query.get_or_404(scan_id)
    result = get_scan_result(scan_id)

    return jsonify({
        'scan_id': scan_id,
        'status': job.status,
        'target': job.target,
        'scan_type': job.scan_type,
        'result': result,
    })


@bp.route('/ssh', methods=['POST'])
def ssh_scan():
    """Execute a remote package audit via SSH."""
    from app.services.ssh_service import scan_host_packages

    body = request.get_json(force=True)
    hostname = body.get('hostname')
    username = body.get('username')
    key_path = body.get('key_path')

    if not all([hostname, username, key_path]):
        return jsonify({'error': 'hostname, username, and key_path are required'}), 400

    result = scan_host_packages(hostname, username, key_path)
    return jsonify(result)
