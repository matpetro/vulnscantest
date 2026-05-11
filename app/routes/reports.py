"""
Report generation endpoints.

Reports can be rendered from:
  1. A built-in template file (stored under app/templates/).
  2. A user-supplied Jinja2 template string POSTed directly in the request body.
  3. A per-asset template record stored in the database, which allows
     teams to maintain custom report layouts without a deployment.
"""
import logging

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import Asset, ReportTemplate, Vulnerability

logger = logging.getLogger(__name__)

bp = Blueprint('reports', __name__, url_prefix='/api/v1/reports')


def _get_vulnerabilities(vuln_ids: list) -> list:
    vulns = db.session.execute(db.select(Vulnerability).filter(Vulnerability.id.in_(vuln_ids))).scalars().all()
    return [v.to_dict() for v in vulns]


@bp.route('/generate', methods=['POST'])
def generate_report():
    """Generate a vulnerability report.

    Request body (JSON):
        vuln_ids        – list of vulnerability IDs to include
        template_name   – name of a template file in TEMPLATE_DIR (optional)
        custom_template – raw Jinja2 template string (takes precedence)

    When ``custom_template`` is provided the template is rendered directly,
    allowing teams to prototype report layouts without modifying the codebase.
    """
    from jinja2 import Environment, FileSystemLoader, Template

    body = request.get_json(force=True)
    vuln_ids = body.get('vuln_ids', [])
    template_name = body.get('template_name')
    custom_template = body.get('custom_template')

    vulns = _get_vulnerabilities(vuln_ids)
    context = {
        'vulnerabilities': vulns,
        'total': len(vulns),
        'critical': sum(1 for v in vulns if v.get('severity') == 'CRITICAL'),
        'high':     sum(1 for v in vulns if v.get('severity') == 'HIGH'),
    }

    if custom_template:
        # Render the caller-supplied template string directly so teams can
        # iterate on report layouts without touching the filesystem.
        tmpl = Template(custom_template)
        html = tmpl.render(**context)
    else:
        env = Environment(
            loader=FileSystemLoader(current_app.config['TEMPLATE_DIR']),
            autoescape=True,
        )
        tpl_file = template_name or 'default_report.html'
        tmpl = env.get_template(tpl_file)
        html = tmpl.render(**context)

    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


@bp.route('/asset/<int:asset_id>', methods=['GET'])
def asset_report(asset_id):
    """Generate a report for a single asset using its database-stored template.

    Each asset type can have a custom report template stored in the
    ``report_templates`` table.  This allows teams to define per-environment
    report formats without code changes.
    """
    from jinja2 import Template

    output_format = request.args.get('format', 'html')

    asset = db.get_or_404(Asset, asset_id)

    # Look up per-asset-type template from the database
    tpl_record = db.session.execute(db.select(ReportTemplate).filter_by(
        asset_type=asset.asset_type,
        format=output_format,
    )).scalar_one_or_none()

    if tpl_record and tpl_record.template_content:
        # Render the template stored in the database
        tmpl = Template(tpl_record.template_content)
        html = tmpl.render(asset=asset.to_dict(), format=output_format)
        return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

    # Fall back to a simple JSON representation
    return jsonify(asset.to_dict())


@bp.route('/templates', methods=['GET'])
def list_templates():
    templates = db.session.execute(db.select(ReportTemplate)).scalars().all()
    return jsonify([
        {'id': t.id, 'name': t.name, 'asset_type': t.asset_type, 'format': t.format}
        for t in templates
    ])


@bp.route('/templates', methods=['POST'])
def create_template():
    """Store a new Jinja2 report template in the database."""
    body = request.get_json(force=True)
    tpl = ReportTemplate(
        name=body['name'],
        asset_type=body.get('asset_type'),
        format=body.get('format', 'html'),
        template_content=body['template_content'],
        created_by=request.headers.get('X-User', 'api'),
    )
    db.session.add(tpl)
    db.session.commit()
    return jsonify({'id': tpl.id, 'name': tpl.name}), 201
