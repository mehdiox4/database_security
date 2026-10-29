# Exporte les données réelles de la base pour illustrer les maquettes (dashboards)
import json, psycopg2, psycopg2.extras
c = psycopg2.connect(dbname="bank_db", cursor_factory=psycopg2.extras.RealDictCursor)
def q(s):
    with c.cursor() as cur:
        cur.execute(s); return cur.fetchall()
d = dict(
  accounts=q("SELECT account_id, left(account_number,4)||'****'||right(account_number,4) AS num, account_type, balance::float, currency FROM bank.account WHERE customer_id=4 ORDER BY 1"),
  txns=q("SELECT to_char(transaction_date,'DD/MM') AS d, transaction_type AS t, amount::float, description FROM bank.bank_transaction WHERE account_id=1005 ORDER BY transaction_date DESC, transaction_id DESC LIMIT 6"),
  benefs=q("SELECT name FROM bank.beneficiary WHERE customer_id=4"),
  loans=q("SELECT amount::float, interest_rate::float, status FROM bank.loan WHERE customer_id=4"),
  stats=q("SELECT (SELECT count(*) FROM bank.app_user) AS users, (SELECT count(*) FROM bank.account) AS accounts, (SELECT count(*) FROM bank.bank_transaction) AS txns, (SELECT count(*) FROM bank.security_alert WHERE status='OPEN') AS alerts, (SELECT count(*) FROM bank.audit_log) AS audit")[0],
  alerts=q("SELECT to_char(created_at,'DD/MM HH24:MI') AS ts, severity, rule_code, description FROM bank.security_alert ORDER BY alert_id DESC"),
  audit=q("SELECT to_char(a.timestamp,'DD/MM HH24:MI:SS') AS ts, COALESCE(u.username, a.db_user) AS usr, a.action, a.table_name AS tbl, COALESCE(host(a.ip_address),'-') AS ip, a.result FROM bank.audit_log a LEFT JOIN bank.app_user u USING(user_id) ORDER BY a.audit_id DESC LIMIT 9"),
  attempts=q("SELECT to_char(attempted_at,'DD/MM HH24:MI:SS') AS ts, username, host(ip_address) AS ip, success FROM bank.login_attempt ORDER BY attempt_id DESC LIMIT 7"),
  attempts_stats=q("SELECT count(*) FILTER (WHERE NOT success) AS failed, count(*) FILTER (WHERE success) AS ok FROM bank.login_attempt")[0],
  alert_by_sev=q("SELECT severity, count(*) AS n FROM bank.security_alert GROUP BY 1 ORDER BY 1"),
  audit_by_table=q("SELECT table_name AS tbl, count(*) AS n FROM bank.audit_log GROUP BY 1 ORDER BY 2 DESC LIMIT 6"),
  audit_rows=q("SELECT count(*) AS n FROM bank.audit_log"),
  txn_total=q("SELECT count(*) AS n FROM bank.bank_transaction"))
json.dump(d, open("/home/claude/bank/build/evidence/data.json", "w"), ensure_ascii=False, indent=1, default=str)
print("export ok")
