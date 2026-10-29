#!/bin/sh
# Durcissement PostgreSQL (exécuté en root ; configuration rechargée à chaud)
PSQL="su postgres -c"
$PSQL "psql -X -q -d postgres" <<'SQL'
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_statement = 'ddl';
ALTER SYSTEM SET log_lock_waits = on;
ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d app=%a ip=%h ';
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.3';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
ALTER ROLE app_backend SET statement_timeout = '15s';
ALTER ROLE app_backend SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE app_backend SET lock_timeout = '5s';
SQL
# Imposer TLS pour toute connexion réseau (host -> hostssl)
sed -i -E 's/^host(\s+)/hostssl\1/' /etc/postgresql/16/main/pg_hba.conf
su postgres -c "psql -X -q -d postgres -c 'SELECT pg_reload_conf()'" >/dev/null
