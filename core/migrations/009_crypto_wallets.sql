-- Migration: Add crypto wallet support
-- Description: Add tables for storing cryptocurrency wallets, addresses, and transactions

-- Crypto wallets table
CREATE TABLE IF NOT EXISTS crypto_wallets (
    id TEXT PRIMARY KEY NOT NULL,
    identity_id TEXT NOT NULL,
    name TEXT NOT NULL CHECK(length(trim(name)) > 0),
    description TEXT,
    network TEXT NOT NULL,
    wallet_type TEXT NOT NULL,
    derivation_path TEXT,
    extended_public_key TEXT,
    encrypted_private_key BLOB NOT NULL,
    encrypted_mnemonic BLOB,
    watch_only INTEGER NOT NULL DEFAULT 0,
    security_level TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE,
    CHECK ((watch_only = 0) OR (watch_only = 1 AND extended_public_key IS NOT NULL))
);

-- Create indexes for crypto_wallets
CREATE INDEX IF NOT EXISTS idx_crypto_wallets_identity_id ON crypto_wallets(identity_id);
CREATE INDEX IF NOT EXISTS idx_crypto_wallets_network ON crypto_wallets(network);
CREATE INDEX IF NOT EXISTS idx_crypto_wallets_security_level ON crypto_wallets(security_level);
CREATE INDEX IF NOT EXISTS idx_crypto_wallets_created_at ON crypto_wallets(created_at DESC);

-- Wallet addresses table
CREATE TABLE IF NOT EXISTS wallet_addresses (
    id TEXT PRIMARY KEY NOT NULL,
    wallet_id TEXT NOT NULL,
    address TEXT NOT NULL CHECK(length(trim(address)) > 0),
    address_type TEXT NOT NULL,
    derivation_path TEXT,
    "index" INTEGER NOT NULL CHECK("index" >= 0),
    used INTEGER NOT NULL DEFAULT 0,
    balance TEXT,
    last_activity INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES crypto_wallets(id) ON DELETE CASCADE,
    UNIQUE(wallet_id, address)
);

-- Create indexes for wallet_addresses
CREATE INDEX IF NOT EXISTS idx_wallet_addresses_wallet_id ON wallet_addresses(wallet_id);
CREATE INDEX IF NOT EXISTS idx_wallet_addresses_address ON wallet_addresses(address);
CREATE INDEX IF NOT EXISTS idx_wallet_addresses_used ON wallet_addresses(used);
CREATE INDEX IF NOT EXISTS idx_wallet_addresses_wallet_index ON wallet_addresses(wallet_id, "index");

-- Wallet metadata table for additional structured data
CREATE TABLE IF NOT EXISTS wallet_metadata (
    wallet_id TEXT PRIMARY KEY NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    platform TEXT,
    purpose TEXT,
    associated_services TEXT NOT NULL DEFAULT '[]',
    backup_info TEXT,
    security_settings TEXT NOT NULL DEFAULT '{}',
    custom_data TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES crypto_wallets(id) ON DELETE CASCADE
);

-- Transaction requests table
CREATE TABLE IF NOT EXISTS transaction_requests (
    id TEXT PRIMARY KEY NOT NULL,
    wallet_id TEXT NOT NULL,
    network TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    amount TEXT NOT NULL CHECK(length(trim(amount)) > 0),
    fee TEXT NOT NULL CHECK(length(trim(fee)) > 0),
    gas_price TEXT,
    gas_limit INTEGER,
    nonce INTEGER,
    memo TEXT,
    raw_transaction_data BLOB,
    required_signatures INTEGER NOT NULL DEFAULT 1 CHECK(required_signatures > 0),
    created_at INTEGER NOT NULL,
    signed_at INTEGER,
    expires_at INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    FOREIGN KEY (wallet_id) REFERENCES crypto_wallets(id) ON DELETE CASCADE
);

-- Create indexes for transaction_requests
CREATE INDEX IF NOT EXISTS idx_transaction_requests_wallet_id ON transaction_requests(wallet_id);
CREATE INDEX IF NOT EXISTS idx_transaction_requests_status ON transaction_requests(status);
CREATE INDEX IF NOT EXISTS idx_transaction_requests_created_at ON transaction_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transaction_requests_expires_at ON transaction_requests(expires_at);

-- Signed transactions table
CREATE TABLE IF NOT EXISTS signed_transactions (
    id TEXT PRIMARY KEY NOT NULL,
    wallet_id TEXT NOT NULL,
    request TEXT NOT NULL,
    signatures TEXT NOT NULL,
    raw_signed_transaction BLOB NOT NULL,
    transaction_hash TEXT NOT NULL CHECK(length(trim(transaction_hash)) > 0),
    signed_at INTEGER NOT NULL,
    broadcast_status TEXT NOT NULL DEFAULT '{"status":"NotBroadcast"}',
    confirmations INTEGER DEFAULT 0 CHECK(confirmations >= 0),
    block_height INTEGER,
    confirmed_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES crypto_wallets(id) ON DELETE CASCADE,
    UNIQUE(transaction_hash)
);

-- Create indexes for signed_transactions
CREATE INDEX IF NOT EXISTS idx_signed_transactions_wallet_id ON signed_transactions(wallet_id);
CREATE INDEX IF NOT EXISTS idx_signed_transactions_transaction_hash ON signed_transactions(transaction_hash);
CREATE INDEX IF NOT EXISTS idx_signed_transactions_signed_at ON signed_transactions(signed_at DESC);
