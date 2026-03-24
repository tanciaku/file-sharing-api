CREATE TABLE files (
    id UUID PRIMARY KEY,
    original_name TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);