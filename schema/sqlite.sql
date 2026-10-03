-- INITIAL SCHEMA ONLY: run once against an empty dedicated database.
PRAGMA foreign_keys=ON;
BEGIN IMMEDIATE;
-- Sekscan schema v1. UTC timestamps use fixed-width RFC3339 microseconds.
-- Apply with sekscan storage migrate; all application writes use transactions.

CREATE TABLE IF NOT EXISTS sekscan_schema_migrations (
 version INTEGER NOT NULL PRIMARY KEY,
 checksum VARCHAR(64) NOT NULL,
 applied_at VARCHAR(27) NOT NULL
);

-- sekscan:statement

CREATE TABLE sekscan_projects (
 id VARCHAR(64) NOT NULL PRIMARY KEY,
 namespace VARCHAR(128) NOT NULL,
 project_key VARCHAR(256) NOT NULL,
 name VARCHAR(256) NOT NULL,
 repository_uri TEXT NOT NULL,
 created_at VARCHAR(27) NOT NULL,
 CONSTRAINT uq_sekscan_project UNIQUE(namespace,project_key)
);

-- sekscan:statement

CREATE TABLE sekscan_scans (
 id VARCHAR(64) NOT NULL PRIMARY KEY,
 project_id VARCHAR(64) NOT NULL REFERENCES sekscan_projects(id),
 started_at VARCHAR(27) NOT NULL,
 finished_at VARCHAR(27) NOT NULL,
 target_kind VARCHAR(32) NOT NULL,
 target_value TEXT NOT NULL,
 target_identity TEXT NOT NULL,
 revision VARCHAR(256) NOT NULL,
 branch VARCHAR(256) NOT NULL,
 app_version VARCHAR(128) NOT NULL,
 config_hash VARCHAR(64) NOT NULL,
 status VARCHAR(16) NOT NULL CHECK(status IN ('passed','failed','incomplete')),
 complete SMALLINT NOT NULL CHECK(complete IN (0,1)),
 exit_code INTEGER NOT NULL CHECK(exit_code IN (0,1,2)),
 summary_json TEXT NOT NULL CHECK (json_valid(summary_json)),
 report_json TEXT NOT NULL CHECK (json_valid(report_json)),
 payload_sha256 VARCHAR(64) NOT NULL,
 stored_at VARCHAR(27) NOT NULL
);

-- sekscan:statement

CREATE TABLE sekscan_engine_runs (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 name VARCHAR(64) NOT NULL,
 version VARCHAR(128) NOT NULL,
 status VARCHAR(16) NOT NULL,
 required SMALLINT NOT NULL CHECK(required IN (0,1)),
 duration_ms BIGINT NOT NULL,
 result_json TEXT NOT NULL CHECK (json_valid(result_json)),
 PRIMARY KEY(scan_id,ordinal)
);

-- sekscan:statement

CREATE TABLE sekscan_components (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 component_id VARCHAR(64) NOT NULL,
 name TEXT NOT NULL,
 version TEXT NOT NULL,
 purl TEXT NOT NULL,
 ecosystem VARCHAR(64) NOT NULL,
 scope VARCHAR(32) NOT NULL,
 component_json TEXT NOT NULL CHECK (json_valid(component_json)),
 PRIMARY KEY(scan_id,component_id)
);

-- sekscan:statement

CREATE TABLE sekscan_findings (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 fingerprint VARCHAR(64) NOT NULL,
 component_id VARCHAR(64) NULL,
 category VARCHAR(32) NOT NULL,
 rule_id TEXT NOT NULL,
 severity VARCHAR(16) NOT NULL,
 scope VARCHAR(32) NOT NULL,
 decision VARCHAR(16) NOT NULL,
 baseline_state VARCHAR(16) NOT NULL,
 resolved SMALLINT NOT NULL CHECK(resolved IN (0,1)),
 finding_json TEXT NOT NULL CHECK (json_valid(finding_json)),
 PRIMARY KEY(scan_id,ordinal)
);

-- sekscan:statement

CREATE TABLE sekscan_artifacts (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 name VARCHAR(128) NOT NULL,
 media_type VARCHAR(128) NOT NULL,
 sha256 VARCHAR(64) NOT NULL,
 size_bytes BIGINT NOT NULL CHECK(size_bytes>=0),
 content BLOB NOT NULL,
 PRIMARY KEY(scan_id,name)
);

-- sekscan:statement

CREATE INDEX ix_sekscan_scans_project_time ON sekscan_scans(project_id,started_at,id);

-- sekscan:statement

CREATE INDEX ix_sekscan_scans_status ON sekscan_scans(status,started_at);

-- sekscan:statement

CREATE INDEX ix_sekscan_findings_fingerprint ON sekscan_findings(fingerprint,scan_id);

-- sekscan:statement

CREATE INDEX ix_sekscan_findings_filter ON sekscan_findings(scan_id,severity,decision,category);

-- sekscan:statement

CREATE INDEX ix_sekscan_components_scope ON sekscan_components(scan_id,scope);

INSERT INTO sekscan_schema_migrations(version,checksum,applied_at) VALUES (1,'389f45d8d6fef9829ebda2bdd2cc69dc1c70f156725925fba9a974b9493e1ae6','2026-10-02T16:34:30.056673Z');
COMMIT;
