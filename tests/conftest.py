"""Shared test fixtures."""
import pytest
from app import create_app
from app.extensions import db as _db


@pytest.fixture(scope='session')
def app():
    """Create application with an in-memory SQLite database for testing."""
    test_cfg = {
        'app': {'secret_key': 'test-secret', 'debug': False, 'testing': True},
        'database': {
            'driver': 'sqlite', 'host': '', 'port': '', 'name': '',
            'user': '', 'password': '',
        },
        'redis': {'host': 'localhost', 'port': 6379},
        'scanning': {'allowed_scan_types': ['basic', 'full'], 'default_timeout': 30},
        'ssh': {'connection_timeout': 10, 'command_timeout': 30},
        'reports': {'template_dir': 'app/templates'},
    }

    application = create_app.__wrapped__(test_cfg) if hasattr(create_app, '__wrapped__') else None

    # Minimal Flask test app bootstrapped without config.yaml
    from flask import Flask
    application = Flask(__name__)
    application.config['TESTING'] = True
    application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    application.config['SECRET_KEY'] = 'test-secret'
    application.config['TEMPLATE_DIR'] = 'app/templates'
    application.config['SCANNING_CONFIG'] = {'allowed_scan_types': ['basic', 'full']}
    application.config['SSH_CONFIG'] = {}

    _db.init_app(application)

    from app.routes import scans, vulnerabilities, reports
    application.register_blueprint(scans.bp)
    application.register_blueprint(vulnerabilities.bp)
    application.register_blueprint(reports.bp)

    with application.app_context():
        _db.create_all()
        yield application
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    with app.app_context():
        yield _db
        _db.session.rollback()
