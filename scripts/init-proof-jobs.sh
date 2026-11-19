#!/bin/sh
# Executed only when the PostgreSQL container initializes a new volume.
WORKER_SECRET=$(cat /db-secrets/worker) psql -v ON_ERROR_STOP=1 --username postgres --dbname proofjobs <<'SQL'
\getenv worker_secret WORKER_SECRET
CREATE ROLE worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'worker_secret';
GRANT CREATE, USAGE ON SCHEMA public TO worker;
SQL
