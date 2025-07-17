-- +migrate Up
CREATE TABLE subdomains (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE endpoints (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    url TEXT NOT NULL,
    method VARCHAR(10) NOT NULL,
    params JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE technologies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE certificates (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE dns_records (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE cloud_assets (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    provider VARCHAR(255) NOT NULL,
    data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION merge_recon_data()
RETURNS TRIGGER AS $$
BEGIN
    -- This is just a placeholder.
    -- In a real application, this would be a more complex merge.
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE INDEX ON subdomains (target_id);
CREATE INDEX ON endpoints (target_id);
CREATE INDEX ON certificates (target_id);
CREATE INDEX ON dns_records (target_id);
CREATE INDEX ON cloud_assets (target_id);

-- +migrate Down
DROP INDEX IF EXISTS subdomains_target_id_idx;
DROP INDEX IF EXISTS endpoints_target_id_idx;
DROP INDEX IF EXISTS certificates_target_id_idx;
DROP INDEX IF EXISTS dns_records_target_id_idx;
DROP INDEX IF EXISTS cloud_assets_target_id_idx;

DROP FUNCTION IF EXISTS merge_recon_data();

DROP TABLE IF EXISTS cloud_assets;
DROP TABLE IF EXISTS dns_records;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS technologies;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS subdomains;
