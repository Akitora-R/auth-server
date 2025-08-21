CREATE SCHEMA IF NOT EXISTS auth;
SET search_path TO auth;

DROP TABLE IF EXISTS auth.auth_user_provider;
DROP TABLE IF EXISTS auth.auth_client;
DROP TABLE IF EXISTS auth.auth_user;

CREATE TABLE auth.auth_user (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255),
    display_name VARCHAR(255),
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

CREATE TABLE auth.auth_user_provider (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
    login_key VARCHAR(255) NOT NULL,
    provider_type VARCHAR(255) NOT NULL,
    provider_data JSONB,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

CREATE TABLE auth.auth_client (
    id VARCHAR(255) PRIMARY KEY,
    display_name VARCHAR(255),
    secret TEXT,
    domain TEXT,
    scopes JSONB,
    token_type VARCHAR(255),
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
