#!/bin/bash
# Exécuté automatiquement par l'image officielle postgres au premier démarrage
# (dossier /docker-entrypoint-initdb.d), AVANT que le serveur n'accepte de connexions
# réseau. Crée la base, les tables, les rôles, les fonctions et les données fictives.
set -e
SQL=/docker-entrypoint-initdb.d/sql

echo "[init] 00_database.sql"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -f "$SQL/00_database.sql"

for f in 01_schema 02_roles 03_functions 04_transfer 05_security 06_seed; do
  echo "[init] $f.sql"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d bank_db -f "$SQL/$f.sql"
done

echo "[init] durcissement (journalisation, délais d'attente)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d postgres <<'SQL'
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_statement = 'ddl';
ALTER SYSTEM SET log_lock_waits = on;
ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d app=%a ip=%h ';
ALTER ROLE app_backend SET statement_timeout = '15s';
ALTER ROLE app_backend SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE app_backend SET lock_timeout = '5s';
SELECT pg_reload_conf();
SQL

echo "[init] terminé."
