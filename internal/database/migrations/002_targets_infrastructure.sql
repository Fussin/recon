-- +migrate Up
CREATE TABLE targets (
    id SERIAL PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES programs(id),
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE target_technologies (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE target_services (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    port INTEGER NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE target_history (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    event_type VARCHAR(255) NOT NULL,
    event_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE target_screenshots (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    screenshot_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE MATERIALIZED VIEW target_statistics AS
SELECT
    t.id AS target_id,
    COUNT(DISTINCT v.id) AS total_vulnerabilities,
    AVG(v.severity) AS avg_severity
FROM
    targets t
LEFT JOIN
    scans s ON t.id = s.target_id
LEFT JOIN
    vulnerabilities v ON s.id = v.scan_id
GROUP BY
    t.id;

CREATE INDEX ON targets (program_id);
CREATE INDEX ON target_technologies (target_id);
CREATE INDEX ON target_services (target_id);
CREATE INDEX ON target_history (target_id);
CREATE INDEX ON target_screenshots (target_id);

-- +migrate Down
DROP INDEX IF EXISTS targets_program_id_idx;
DROP INDEX IF EXISTS target_technologies_target_id_idx;
DROP INDEX IF EXISTS target_services_target_id_idx;
DROP INDEX IF EXISTS target_history_target_id_idx;
DROP INDEX IF EXISTS target_screenshots_target_id_idx;

DROP MATERIALIZED VIEW IF EXISTS target_statistics;
DROP TABLE IF EXISTS target_screenshots;
DROP TABLE IF EXISTS target_history;
DROP TABLE IF EXISTS target_services;
DROP TABLE IF EXISTS target_technologies;
DROP TABLE IF EXISTS targets;
