#!/bin/sh
# Requêtes d'investigation (exécutées en superutilisateur DBA, lecture seule)
E=/home/claude/bank/build/evidence; P="psql -X -d bank_db"
T0=$(python3 -c "import json;print(json.load(open('$E/incident_run.json'))['t0'])")
{
echo "-- Q1 : échecs de connexion par source et par compte"
$P -c "SELECT host(ip_address) AS ip, username, count(*) FILTER (WHERE NOT success) AS echecs, count(*) FILTER (WHERE success) AS succes FROM bank.login_attempt WHERE attempted_at >= '$T0' GROUP BY 1,2 ORDER BY echecs DESC"
echo "-- Q2 : succès précédé d'échecs depuis la même IP"
$P -c "SELECT s.username, host(s.ip_address) AS ip, to_char(s.attempted_at,'HH24:MI:SS') AS succes_a, (SELECT count(*) FROM bank.login_attempt f WHERE f.username=s.username AND NOT f.success AND f.ip_address=s.ip_address AND f.attempted_at < s.attempted_at AND f.attempted_at >= '$T0') AS echecs_avant FROM bank.login_attempt s WHERE s.success AND s.attempted_at >= '$T0' AND s.ip_address = '185.220.101.45'"
echo "-- Q3 : lectures de données sensibles depuis l'IP suspecte"
$P -c "SELECT a.audit_id, u.username, a.record_id AS client, a.new_value->>'field' AS champ, a.new_value->>'reason' AS motif FROM bank.audit_log a JOIN bank.app_user u USING(user_id) WHERE a.action='READ_SENSITIVE' AND a.ip_address='185.220.101.45' ORDER BY 1"
echo "-- Q4 : alertes générées pendant l'incident"
$P -c "SELECT alert_id, to_char(created_at,'HH24:MI:SS') AS heure, severity, rule_code, description FROM bank.security_alert WHERE created_at >= '$T0' ORDER BY 1"
echo "-- Q5 : vérification d'intégrité comptable après l'incident"
$P -c "SELECT count(*) AS ecarts_solde_journal FROM bank.v_balance_reconciliation WHERE gap <> 0"
echo "-- Q6 : journal PostgreSQL (refus de privilèges, compte manager01)"
grep -E "permission denied" /var/log/postgresql/postgresql-16-main.log | grep "app=manager01" | tail -3 | cut -c1-210
grep -E -A1 "permission denied" /var/log/postgresql/postgresql-16-main.log | grep -E "STATEMENT" | tail -3 | cut -c1-120
} > $E/investigation.txt 2>&1
# chronologie unifiée (pour le rapport)
$P -At -F '|' -c "SELECT to_char(ts,'HH24:MI:SS'), src, who, ip, what FROM (
 SELECT attempted_at AS ts, 'login' AS src, username AS who, host(ip_address) AS ip, CASE WHEN success THEN 'connexion réussie' ELSE 'échec de connexion' END AS what FROM bank.login_attempt WHERE attempted_at >= '$T0'
 UNION ALL SELECT a.timestamp, 'audit', COALESCE(u.username,a.db_user), host(a.ip_address), a.action||' '||a.table_name||' #'||COALESCE(a.record_id::text,'') FROM bank.audit_log a LEFT JOIN bank.app_user u USING(user_id) WHERE a.timestamp >= '$T0' AND a.table_name <> 'security_alert'
 UNION ALL SELECT created_at, 'alerte', rule_code, '', description FROM bank.security_alert WHERE created_at >= '$T0'
) x ORDER BY ts" > $E/timeline.psv
