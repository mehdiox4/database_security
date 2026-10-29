#!/bin/sh
cd /home/claude/bank/sql
su postgres -c "psql -q -c 'DROP DATABASE IF EXISTS bank_db' -c 'DROP ROLE IF EXISTS app_backend' -c 'DROP ROLE IF EXISTS backup_svc' -c 'DROP ROLE IF EXISTS role_client' -c 'DROP ROLE IF EXISTS role_employee' -c 'DROP ROLE IF EXISTS role_manager' -c 'DROP ROLE IF EXISTS role_admin' -c 'DROP ROLE IF EXISTS role_auditor' -c 'DROP ROLE IF EXISTS bank_owner'" 2>&1 | grep -v NOTICE
for f in 00_database 01_schema 02_roles 03_functions 04_transfer 05_security 06_seed; do
  echo "== $f"; DBN=bank_db; [ $f = 00_database ] && DBN=postgres; su postgres -c "psql -q -v ON_ERROR_STOP=1 -d $DBN -f /home/claude/bank/sql/$f.sql" 2>&1 | grep -v NOTICE | head -20
done
