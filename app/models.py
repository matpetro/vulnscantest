import datetime
from app.extensions import db


class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False, unique=True)
    ip_address = db.Column(db.String(45))
    asset_type = db.Column(db.String(64))          # server, workstation, network, cloud
    environment = db.Column(db.String(64))          # production, staging, development
    os_name = db.Column(db.String(128))
    os_version = db.Column(db.String(64))
    agent_version = db.Column(db.String(32))
    last_scan_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow)
    deleted_at = db.Column(db.DateTime)

    vulnerabilities = db.relationship('Vulnerability', back_populates='asset', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'asset_type': self.asset_type,
            'environment': self.environment,
            'os_name': self.os_name,
            'os_version': self.os_version,
        }


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    cve_id = db.Column(db.String(32))
    title = db.Column(db.String(512))
    description = db.Column(db.Text)
    severity = db.Column(db.String(16))     # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score = db.Column(db.Numeric(4, 1))
    cvss_vector = db.Column(db.String(128))
    affected_package = db.Column(db.String(255))
    affected_version = db.Column(db.String(128))
    fixed_version = db.Column(db.String(128))
    status = db.Column(db.String(32), default='open')  # open, in_progress, resolved, accepted
    scanner_name = db.Column(db.String(64))
    raw_finding = db.Column(db.JSON)
    discovered_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)

    asset = db.relationship('Asset', back_populates='vulnerabilities')

    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'title': self.title,
            'severity': self.severity,
            'cvss_score': float(self.cvss_score) if self.cvss_score else None,
            'affected_package': self.affected_package,
            'affected_version': self.affected_version,
            'fixed_version': self.fixed_version,
            'status': self.status,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
        }


class ScanJob(db.Model):
    __tablename__ = 'scan_jobs'

    id = db.Column(db.String(36), primary_key=True)  # UUID
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'))
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(32), default='basic')
    ports = db.Column(db.String(128))
    status = db.Column(db.String(32), default='pending')  # pending, running, completed, failed
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class ReportTemplate(db.Model):
    """User-managed Jinja2 report templates stored in the database."""
    __tablename__ = 'report_templates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True)
    asset_type = db.Column(db.String(64))
    format = db.Column(db.String(16), default='html')  # html, markdown
    template_content = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow)
