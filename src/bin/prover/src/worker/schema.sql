-- Public job metadata. Witness bytes never enter this table.
CREATE TABLE IF NOT EXISTS proof_jobs (
    chain text NOT NULL,
    guest bytea NOT NULL,
    commitment bytea NOT NULL,
    height text NOT NULL,
    result bytea,
    attempts integer NOT NULL DEFAULT 0,
    queued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    queue_ms bigint,
    runtime_ms bigint,
    rejection text,
    PRIMARY KEY (chain, guest, commitment),
    CHECK (num_nonnulls(result, rejection) <= 1)
);

-- Private witness reference. Removed in the same transaction as completion.
CREATE TABLE IF NOT EXISTS proof_job_witness (
    chain text NOT NULL,
    guest bytea NOT NULL,
    commitment bytea NOT NULL,
    payload bytea NOT NULL,
    PRIMARY KEY (chain, guest, commitment),
    FOREIGN KEY (chain, guest, commitment)
        REFERENCES proof_jobs (chain, guest, commitment) ON DELETE CASCADE
);

-- Operator/monitoring view: status and timing only, no witness or proof bytes.
CREATE OR REPLACE VIEW proof_job_status AS
    SELECT chain, guest, commitment, height, attempts, queued_at,
           queue_ms, runtime_ms, rejection,
           result IS NOT NULL AS complete
    FROM proof_jobs;
