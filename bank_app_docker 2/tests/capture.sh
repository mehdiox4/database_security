#!/bin/sh
# Capture des sorties réelles (exécuté en tant qu'utilisateur postgres)
E=/home/claude/bank/build/evidence
P="psql -X -d bank_db"
$P -c '\dt bank.*' > $E/tables.txt
$P -c "SELECT rolname, rolcanlogin AS login, rolinherit AS inherit, rolbypassrls AS bypassrls FROM pg_roles WHERE rolname LIKE 'role\_%' OR rolname IN ('app_backend','backup_svc','bank_owner') ORDER BY 1" > $E/roles.txt
$P -c "SELECT tablename, policyname, roles, cmd FROM pg_policies WHERE schemaname='bank' ORDER BY tablename, policyname" > $E/policies.txt
$P -c "SELECT tgrelid::regclass AS table_name, tgname AS trigger_name FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1,2" > $E/triggers.txt
$P -c "SELECT relname, relrowsecurity AS rls_enabled FROM pg_class WHERE relnamespace='bank'::regnamespace AND relkind='r' ORDER BY 1" > $E/rls_flags.txt
psql -X -a -d postgres -f /home/claude/bank/tests/tx_demo.sql > $E/tx_demo.txt 2>&1
$P -c "SELECT a.audit_id, u.username, a.action, a.table_name AS tbl, a.record_id AS rec, host(a.ip_address) AS ip, a.old_value, a.new_value, a.result FROM bank.audit_log a LEFT JOIN bank.app_user u USING(user_id) WHERE a.table_name='account' AND a.new_value ? 'balance' ORDER BY a.audit_id DESC LIMIT 4" > $E/audit_balance.txt
$P -c "SELECT customer_id, left(encode(national_id,'hex'),36) || '…' AS national_id_chiffre, national_id_last4 FROM bank.customer ORDER BY 1 LIMIT 3" > $E/encrypted.txt
$P -c "SELECT customer_id, pgp_sym_decrypt(national_id, 'DEMO-ONLY-KEY-2026-CHANGE-ME') AS national_id_dechiffre FROM bank.customer WHERE customer_id=1" >> $E/encrypted.txt
$P -c "SELECT name, setting FROM pg_settings WHERE name IN ('ssl','ssl_min_protocol_version','password_encryption','wal_level','synchronous_commit','fsync','full_page_writes','default_transaction_isolation') ORDER BY 1" > $E/settings.txt
# ---- sauvegarde / restauration réelles
{
export PGPASSWORD='Backup#Demo2026'
rm -f /tmp/bank_db.dump
echo '$ pg_dump -h "${PGHOST:-localhost}" -U backup_svc -d bank_db -Fc -f bank_db.dump'
pg_dump -h "${PGHOST:-localhost}" -U backup_svc -d bank_db -Fc -f /tmp/bank_db.dump && echo "(dump créé)"
ls -l /tmp/bank_db.dump | awk '{print $5 " octets  " $9}'
sha256sum /tmp/bank_db.dump | cut -c1-64
unset PGPASSWORD
echo '$ createdb bank_restore ; pg_restore --no-owner -d bank_restore bank_db.dump'
psql -X -d postgres -qc 'DROP DATABASE IF EXISTS bank_restore' -c 'CREATE DATABASE bank_restore'
pg_restore --no-owner -d bank_restore /tmp/bank_db.dump 2>&1 | head -5
echo '-- comparaison du nombre de lignes (production vs restauration)'
for t in customer account bank_transaction transfer audit_log security_alert app_user; do
  a=$(psql -X -At -d bank_db -c "SELECT count(*) FROM bank.$t")
  b=$(psql -X -At -d bank_restore -c "SELECT count(*) FROM bank.$t")
  printf '%-18s production=%-4s restauration=%-4s %s\n' $t $a $b $([ "$a" = "$b" ] && echo OK || echo ECART)
done
echo '-- contrôle d intégrité après restauration'
psql -X -d bank_restore -c "SELECT count(*) AS ecarts_solde_vs_journal FROM bank.v_balance_reconciliation WHERE gap <> 0" -c "SELECT count(*) AS triggers_restaures FROM pg_trigger WHERE NOT tgisinternal"
psql -X -d postgres -qc 'DROP DATABASE bank_restore'
} > $E/backup.txt 2>&1
