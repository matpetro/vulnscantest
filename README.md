# VulnScan API

A REST API for ingesting, managing, and reporting on vulnerability scan results from multiple scanner backends (Nmap, OpenVAS, Nessus, Qualys).

## Features

- Ingest raw scan results and normalize them into a unified schema
- Track vulnerabilities across an asset inventory with severity scoring (CVSS)
- Generate customizable HTML/PDF reports with user-supplied templates
- SSH-based remote scanner agent execution and result retrieval
- Redis-backed result caching for high-throughput ingestion pipelines
- Multi-format image attachment support for scan evidence screenshots

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | Flask 1.1.4 |
| ORM | SQLAlchemy 1.4 |
| Database | PostgreSQL 13+ |
| Cache | Redis 6+ |
| WSGI | Gunicorn |
| Image | Pillow |
| SSH | Paramiko |

## Configuration

Application configuration is loaded from `config.yaml` at startup. Environment-specific values (database credentials, API keys, paths) are resolved directly from environment variables using YAML type tags, avoiding the need to duplicate values across both YAML and `.env` files.

```bash
export POSTGRES_HOST=localhost
export POSTGRES_USER=vulnscan
export POSTGRES_PASSWORD=secret
export SECRET_KEY=your-secret-key
```

## Running

```bash
pip install -r requirements.txt
export CONFIG_PATH=config.yaml
gunicorn -c gunicorn.conf.py "app:create_app()"
```

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/vulnerabilities/search` | Search with filters (CVE ID, severity, asset, date range) |
| `POST` | `/api/v1/vulnerabilities/bulk-update` | Bulk update vulnerability status |
| `GET` | `/api/v1/vulnerabilities/asset-summary` | Aggregated summary by asset |
| `POST` | `/api/v1/scans` | Trigger a new Nmap/OpenVAS scan |
| `GET` | `/api/v1/scans/{id}` | Retrieve scan result by ID |
| `POST` | `/api/v1/reports/generate` | Generate vulnerability report (supports custom templates) |
| `POST` | `/api/v1/assets/{id}/ssh-scan` | Execute remote SSH-based package audit |

## Development

```bash
# Run tests
pytest tests/ -v

# Run with debug mode
FLASK_ENV=development flask run
```
