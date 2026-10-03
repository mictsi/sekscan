-- Sekscan schema v1. UTC timestamps use fixed-width RFC3339 microseconds.
-- Apply with sekscan storage migrate; all application writes use transactions.

IF OBJECT_ID(N'sekscan_schema_migrations', N'U') IS NULL
BEGIN
CREATE TABLE sekscan_schema_migrations (
 version INTEGER NOT NULL PRIMARY KEY,
 checksum VARCHAR(64) NOT NULL,
 applied_at VARCHAR(27) NOT NULL
);
END;

-- sekscan:statement

CREATE TABLE sekscan_projects (
 id VARCHAR(64) NOT NULL PRIMARY KEY,
 namespace NVARCHAR(128) COLLATE Latin1_General_100_BIN2 NOT NULL,
 project_key NVARCHAR(256) COLLATE Latin1_General_100_BIN2 NOT NULL,
 name NVARCHAR(256) NOT NULL,
 repository_uri NVARCHAR(MAX) NOT NULL,
 created_at VARCHAR(27) NOT NULL,
 CONSTRAINT uq_sekscan_project UNIQUE(namespace,project_key)
);

-- sekscan:statement

CREATE TABLE sekscan_scans (
 id VARCHAR(64) NOT NULL PRIMARY KEY,
 project_id VARCHAR(64) NOT NULL REFERENCES sekscan_projects(id),
 started_at VARCHAR(27) NOT NULL,
 finished_at VARCHAR(27) NOT NULL,
 target_kind NVARCHAR(32) NOT NULL,
 target_value NVARCHAR(MAX) NOT NULL,
 target_identity NVARCHAR(MAX) NOT NULL,
 revision NVARCHAR(256) NOT NULL,
 branch NVARCHAR(256) NOT NULL,
 app_version NVARCHAR(128) NOT NULL,
 config_hash VARCHAR(64) NOT NULL,
 status NVARCHAR(16) NOT NULL CHECK(status IN ('passed','failed','incomplete')),
 complete SMALLINT NOT NULL CHECK(complete IN (0,1)),
 exit_code INTEGER NOT NULL CHECK(exit_code IN (0,1,2)),
 summary_json NVARCHAR(MAX) NOT NULL CHECK (ISJSON(summary_json)=1),
 report_json NVARCHAR(MAX) NOT NULL CHECK (ISJSON(report_json)=1),
 payload_sha256 VARCHAR(64) NOT NULL,
 stored_at VARCHAR(27) NOT NULL
);

-- sekscan:statement

CREATE TABLE sekscan_engine_runs (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 name NVARCHAR(64) NOT NULL,
 version NVARCHAR(128) NOT NULL,
 status NVARCHAR(16) NOT NULL,
 required SMALLINT NOT NULL CHECK(required IN (0,1)),
 duration_ms BIGINT NOT NULL,
 result_json NVARCHAR(MAX) NOT NULL CHECK (ISJSON(result_json)=1),
 PRIMARY KEY(scan_id,ordinal)
);

-- sekscan:statement

CREATE TABLE sekscan_components (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 component_id VARCHAR(64) NOT NULL,
 name NVARCHAR(MAX) NOT NULL,
 version NVARCHAR(MAX) NOT NULL,
 purl NVARCHAR(MAX) NOT NULL,
 ecosystem NVARCHAR(64) NOT NULL,
 scope NVARCHAR(32) NOT NULL,
 component_json NVARCHAR(MAX) NOT NULL CHECK (ISJSON(component_json)=1),
 PRIMARY KEY(scan_id,component_id)
);

-- sekscan:statement

CREATE TABLE sekscan_findings (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 fingerprint VARCHAR(64) NOT NULL,
 component_id VARCHAR(64) NULL,
 category NVARCHAR(32) NOT NULL,
 rule_id NVARCHAR(MAX) NOT NULL,
 severity NVARCHAR(16) NOT NULL,
 scope NVARCHAR(32) NOT NULL,
 decision NVARCHAR(16) NOT NULL,
 baseline_state NVARCHAR(16) NOT NULL,
 resolved SMALLINT NOT NULL CHECK(resolved IN (0,1)),
 finding_json NVARCHAR(MAX) NOT NULL CHECK (ISJSON(finding_json)=1),
 PRIMARY KEY(scan_id,ordinal)
);

-- sekscan:statement

CREATE TABLE sekscan_artifacts (
 scan_id VARCHAR(64) NOT NULL REFERENCES sekscan_scans(id) ON DELETE CASCADE,
 name NVARCHAR(128) NOT NULL,
 media_type NVARCHAR(128) NOT NULL,
 sha256 VARCHAR(64) NOT NULL,
 size_bytes BIGINT NOT NULL CHECK(size_bytes>=0),
 content VARBINARY(MAX) NOT NULL,
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
