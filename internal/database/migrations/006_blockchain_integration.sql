-- +migrate Up
CREATE TABLE blockchain_transactions (
    id SERIAL PRIMARY KEY,
    transaction_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE smart_contract_addresses (
    id SERIAL PRIMARY KEY,
    address VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ipfs_hashes (
    id SERIAL PRIMARY KEY,
    hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE wallet_addresses (
    id SERIAL PRIMARY KEY,
    address VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE gas_price_history (
    id SERIAL PRIMARY KEY,
    price BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE consensus_validations (
    id SERIAL PRIMARY KEY,
    is_valid BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION verify_blockchain_integrity()
RETURNS TRIGGER AS $$
BEGIN
    -- This is just a placeholder.
    -- In a real application, this would be a more complex verification.
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- +migrate Down
DROP FUNCTION IF EXISTS verify_blockchain_integrity();
DROP TABLE IF EXISTS consensus_validations;
DROP TABLE IF EXISTS gas_price_history;
DROP TABLE IF EXISTS wallet_addresses;
DROP TABLE IF EXISTS ipfs_hashes;
DROP TABLE IF EXISTS smart_contract_addresses;
DROP TABLE IF EXISTS blockchain_transactions;
