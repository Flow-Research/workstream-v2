#!/bin/sh
# Executed only when the PostgreSQL container initializes a new volume.
set -eu
PROJECTION_SECRET=$(cat /db-secrets/projection) psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
\getenv projection_secret PROJECTION_SECRET
CREATE ROLE projection LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'projection_secret';
CREATE DATABASE projections OWNER projection;
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname projections -c \
  'GRANT CREATE, USAGE ON SCHEMA public TO projection'
