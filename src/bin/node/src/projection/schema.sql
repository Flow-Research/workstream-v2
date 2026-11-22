-- Projection cursor. One row per chain; advanced only in the same database
-- transaction as the derived rows for a verified block.
CREATE TABLE IF NOT EXISTS projection_meta (
    chain text PRIMARY KEY,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    verified_height bigint NOT NULL DEFAULT 0 CHECK (verified_height >= 0),
    indexed_height bigint NOT NULL DEFAULT 0 CHECK (indexed_height >= 0),
    indexed_state_root bytea NOT NULL,
    indexed_da_ref bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (indexed_height <= verified_height)
);

-- Immutable replay log written only after full verifier acceptance. Wiping a
-- projection never removes this table.
CREATE TABLE IF NOT EXISTS verified_blocks (
    chain text NOT NULL,
    height bigint NOT NULL CHECK (height > 0),
    block bytea NOT NULL,
    state_root bytea NOT NULL,
    da_ref bytea NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (chain, height),
    UNIQUE (chain, da_ref)
);

CREATE TABLE IF NOT EXISTS projection_events (
    chain text NOT NULL,
    height bigint NOT NULL,
    tx_index bigint NOT NULL,
    ordinal bigint NOT NULL,
    tx_hash bytea NOT NULL,
    event_type text NOT NULL,
    data bytea NOT NULL,
    PRIMARY KEY (chain, height, tx_index, ordinal)
);
CREATE INDEX IF NOT EXISTS projection_events_type
    ON projection_events (chain, event_type, height, tx_index, ordinal);
CREATE INDEX IF NOT EXISTS projection_events_tx
    ON projection_events (chain, tx_hash);

CREATE TABLE IF NOT EXISTS projection_work_items (
    chain text NOT NULL,
    id text NOT NULL,
    height bigint NOT NULL,
    tx_index bigint NOT NULL,
    ordinal bigint NOT NULL,
    kind text NOT NULL,
    subject bytea NOT NULL,
    actor bytea NOT NULL,
    tx_hash bytea NOT NULL,
    data bytea NOT NULL,
    PRIMARY KEY (chain, id)
);
CREATE INDEX IF NOT EXISTS projection_work_items_subject
    ON projection_work_items (chain, subject, height);
CREATE INDEX IF NOT EXISTS projection_work_items_actor
    ON projection_work_items (chain, actor, height);
CREATE INDEX IF NOT EXISTS projection_work_items_height
    ON projection_work_items (chain, height, tx_index, ordinal);

CREATE TABLE IF NOT EXISTS projection_grants (
    chain text NOT NULL,
    grantee bytea NOT NULL,
    grantor bytea NOT NULL,
    capability text NOT NULL CHECK (capability IN ('ClaimWork', 'SubmitWork')),
    active boolean NOT NULL,
    height bigint NOT NULL,
    tx_index bigint NOT NULL,
    ordinal bigint NOT NULL,
    tx_hash bytea NOT NULL,
    PRIMARY KEY (chain, grantee, grantor, capability)
);
CREATE INDEX IF NOT EXISTS projection_grants_height
    ON projection_grants (chain, height, tx_index, ordinal);

CREATE TABLE IF NOT EXISTS projection_reviews (
    chain text NOT NULL,
    id text NOT NULL,
    height bigint NOT NULL,
    tx_index bigint NOT NULL,
    ordinal bigint NOT NULL,
    submission bytea NOT NULL,
    reviewer bytea NOT NULL,
    lease bytea NOT NULL,
    decision text NOT NULL,
    record_index bigint,
    tx_hash bytea NOT NULL,
    PRIMARY KEY (chain, id)
);
CREATE INDEX IF NOT EXISTS projection_reviews_height
    ON projection_reviews (chain, height, tx_index, ordinal);
CREATE INDEX IF NOT EXISTS projection_reviews_submission
    ON projection_reviews (chain, submission, height);

CREATE TABLE IF NOT EXISTS projection_receipts (
    chain text NOT NULL,
    tx_hash bytea NOT NULL,
    height bigint NOT NULL,
    tx_index bigint NOT NULL,
    ordinal bigint NOT NULL,
    status text NOT NULL CHECK (status = 'Verified'),
    PRIMARY KEY (chain, tx_hash)
);
CREATE INDEX IF NOT EXISTS projection_receipts_height
    ON projection_receipts (chain, height, tx_index, ordinal);

-- Public read view: cursor plus computed lag. No private witness or payload
-- bytes are exposed, and this view has no authority over transaction admission.
CREATE OR REPLACE VIEW projection_status AS
    SELECT chain, schema_version, verified_height, indexed_height,
           verified_height - indexed_height AS lag,
           updated_at
    FROM projection_meta;
