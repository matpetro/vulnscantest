-- Initial schema for VulnScan API
-- PostgreSQL 13+

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE assets (
    id          SERIAL PRIMARY KEY,
    hostname    VARCHAR(255) NOT NULL UNIQUE,
    ip_address  VARCHAR(45),
    asset_type  VARCHAR(64),
    environment VARCHAR(64),
    os_name     VARCHAR(128),
    os_version  VARCHAR(64),
    agent_version VARCHAR(32),
    last_scan_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ,
    deleted_at    TIMESTAMPTZ
);

CREATE INDEX idx_assets_environment ON assets (environment);
CREATE INDEX idx_assets_asset_type  ON assets (asset_type);

CREATE TABLE vulnerabilities (
    id                SERIAL PRIMARY KEY,
    asset_id          INTEGER NOT NULL REFERENCES assets(id),
    cve_id            VARCHAR(32),
    title             VARCHAR(512),
    description       TEXT,
    severity          VARCHAR(16),
    cvss_score        NUMERIC(4,1),
    cvss_vector       VARCHAR(128),
    affected_package  VARCHAR(255),
    affected_version  VARCHAR(128),
    fixed_version     VARCHAR(128),
    status            VARCHAR(32) NOT NULL DEFAULT 'open',
    scanner_name      VARCHAR(64),
    raw_finding       JSONB,
    discovered_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ,
    resolved_at       TIMESTAMPTZ,
    deleted_at        TIMESTAMPTZ
);

CREATE INDEX idx_vulns_asset_id    ON vulnerabilities (asset_id);
CREATE INDEX idx_vulns_cve_id      ON vulnerabilities (cve_id);
CREATE INDEX idx_vulns_severity    ON vulnerabilities (severity);
CREATE INDEX idx_vulns_status      ON vulnerabilities (status);
CREATE INDEX idx_vulns_discovered  ON vulnerabilities (discovered_at);

CREATE TABLE scan_jobs (
    id            VARCHAR(36) PRIMARY KEY,   -- UUID
    asset_id      INTEGER REFERENCES assets(id),
    target        VARCHAR(255) NOT NULL,
    scan_type     VARCHAR(32) NOT NULL DEFAULT 'basic',
    ports         VARCHAR(128),
    status        VARCHAR(32) NOT NULL DEFAULT 'pending',
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE report_templates (
    id               SERIAL PRIMARY KEY,
    name             VARCHAR(128) NOT NULL UNIQUE,
    asset_type       VARCHAR(64),
    format           VARCHAR(16) NOT NULL DEFAULT 'html',
    template_content TEXT NOT NULL,
    created_by       VARCHAR(128),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ
);

-- Seed sample data
INSERT INTO assets (hostname, ip_address, asset_type, environment, os_name, os_version) VALUES
    ('web-prod-01', '10.0.1.10', 'server', 'production',  'Ubuntu', '20.04'),
    ('web-prod-02', '10.0.1.11', 'server', 'production',  'Ubuntu', '20.04'),
    ('db-prod-01',  '10.0.2.10', 'server', 'production',  'RHEL',   '8.5'),
    ('ci-runner-01','10.0.3.10', 'server', 'staging',     'Ubuntu', '22.04'),
    ('dev-laptop-42','192.168.1.50','workstation','development','macOS','13.2');
