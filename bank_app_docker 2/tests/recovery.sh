#!/bin/sh
# Phase 8 : sauvegarde, perte de données simulée, restauration, vérification (sorties réelles)
E=/home/claude/bank/build/evidence; D=/tmp/bank_full.dump
export PGPASSWORD='Backup#Demo2026'
L="psql -X -q -d bank_lab"
{
echo '$ pg_dump -h "${PGHOST:-localhost}" -U backup_svc -d bank_db -Fc -f bank_full.dump'
pg_dump -h "${PGHOST:-localhost}" -U backup_svc -d bank_db -Fc -f $D && ls -l $D | awk '{print $5 " octets"}'
unset PGPASSWORD
psql -X -q -d postgres -c 'DROP DATABASE IF EXISTS bank_lab' -c 'CREATE DATABASE bank_lab'
pg_restore --no-owner -d bank_lab $D 2>&1 | head -3
echo '-- empreinte AVANT sinistre (journal comptable)'
$L -At -c "SELECT count(*) || ' lignes, md5=' || md5(string_agg(transaction_id||'|'||account_id||'|'||transaction_type||'|'||amount||'|'||balance_after, ',' ORDER BY transaction_id)) FROM bank.bank_transaction"
echo '-- SINISTRE : suppression accidentelle de la table bank_transaction'
$L -c 'DROP TABLE bank.bank_transaction CASCADE'
$L -c "SELECT to_regclass('bank.bank_transaction') AS table_apres_sinistre"
CHK() { $L -At -c "SELECT 'triggers=' || (SELECT count(*) FROM pg_trigger WHERE tgrelid='bank.bank_transaction'::regclass AND NOT tgisinternal) || ' ; politiques RLS=' || (SELECT count(*) FROM pg_policies WHERE tablename='bank_transaction') || ' ; RLS actif=' || (SELECT relrowsecurity FROM pg_class WHERE oid='bank.bank_transaction'::regclass) || ' ; SELECT role_client=' || has_table_privilege('role_client','bank.bank_transaction','SELECT') || ' ; lignes=' || (SELECT count(*) FROM bank.bank_transaction)"; }
echo '-- TENTATIVE A : pg_restore -t bank_transaction (restauration par nom de table)'
pg_restore --no-owner -d bank_lab -n bank -t bank_transaction -t v_balance_reconciliation $D 2>&1 | head -3
CHK
echo '-- => la table est revenue MAIS sans triggers ni RLS : restauration incomplète et dangereuse'
$L -q -c 'DROP TABLE bank.bank_transaction CASCADE' 2>/dev/null
echo '-- TENTATIVE B : restauration pilotée par la table des matières (pg_restore -l / -L)'
pg_restore -l $D | grep -E "bank_transaction|ix_txn_account_date|v_balance_reconciliation|trg_txn" > /tmp/restore.list
echo "entrées sélectionnées : $(wc -l < /tmp/restore.list)  (TABLE, DATA, CONSTRAINT, INDEX, TRIGGER, POLICY, ACL, ROW SECURITY, FK...)"
pg_restore --no-owner -d bank_lab -L /tmp/restore.list $D 2>&1 | head -3
CHK
echo '-- empreinte APRÈS restauration complète'
$L -At -c "SELECT count(*) || ' lignes, md5=' || md5(string_agg(transaction_id||'|'||account_id||'|'||transaction_type||'|'||amount||'|'||balance_after, ',' ORDER BY transaction_id)) FROM bank.bank_transaction"
echo '-- contrôles d intégrité'
$L -c "SELECT count(*) AS ecarts_solde_journal FROM bank.v_balance_reconciliation WHERE gap <> 0"
echo '-- le journal est de nouveau protégé (DELETE refusé par trigger) :'
$L -c "DELETE FROM bank.bank_transaction WHERE transaction_id = 1" 2>&1 | head -2
psql -X -q -d postgres -c 'DROP DATABASE bank_lab'
} > $E/recovery.txt 2>&1
