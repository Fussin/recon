-- +migrate Up
CREATE TABLE scan_jobs (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_results (
    id SERIAL PRIMARY KEY,
    scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_workers (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_queues (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    config JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON scan_jobs (target_id);
CREATE INDEX ON scan_results (scan_job_id);
CREATE INDEX ON scan_results (vulnerability_id);

-- +migrate Down
DROP INDEX IF EXISTS scan_jobs_target_id_idx;
DROP INDEX IF EXISTS scan_results_scan_job_id_idx;
DROP INDEX IF EXISTS scan_results_vulnerability_id_idx;

DROP TABLE IF EXISTS scan_configs;
DROP TABLE IF EXISTS scan_queues;
DROP TABLE IF EXISTS scan_workers;
DROP TABLE IF EXISTS scan_results;
DROP TABLE IF EXISTS scan_jobs;
