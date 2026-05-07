import os
from flask import Flask
from app.extensions import db
from app.config_loader import load_config


def create_app(config_path: str = None) -> Flask:
    """Application factory."""
    app = Flask(__name__)

    cfg = load_config(config_path)

    db_cfg = cfg.get('database', {})
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"postgresql://{db_cfg.get('user')}:{db_cfg.get('password')}"
        f"@{db_cfg.get('host')}:{db_cfg.get('port')}/{db_cfg.get('name')}"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = cfg['app']['secret_key']
    app.config['TEMPLATE_DIR'] = cfg.get('reports', {}).get('template_dir', 'app/templates')
    app.config['SCANNING_CONFIG'] = cfg.get('scanning', {})
    app.config['SSH_CONFIG'] = cfg.get('ssh', {})

    db.init_app(app)

    from app.routes import scans, vulnerabilities, reports
    app.register_blueprint(scans.bp)
    app.register_blueprint(vulnerabilities.bp)
    app.register_blueprint(reports.bp)

    return app
