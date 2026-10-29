#!/bin/sh
# Phase 2 : CREATE ROLE / GRANT / REVOKE / SHOW GRANTS / test des privilèges (sorties réelles)
E=/home/claude/bank/build/evidence
{
cat <<'SQL' | psql -X -a -d bank_db 2>&1 | sed 's#psql:[^ ]*:\([0-9]*\):#psql:\1:#'
CREATE ROLE temp_stagiaire NOLOGIN;
GRANT role_employee TO temp_stagiaire;
SET ROLE temp_stagiaire;
SELECT account_id, account_number_masked FROM bank.v_account_masked LIMIT 2;
SELECT balance FROM bank.account LIMIT 1;
RESET ROLE;
REVOKE role_employee FROM temp_stagiaire;
SET ROLE temp_stagiaire;
SELECT account_id FROM bank.v_account_masked LIMIT 1;
RESET ROLE;
SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee='role_client' AND table_schema='bank' ORDER BY 2,3;
DROP ROLE temp_stagiaire;
SQL
} > $E/privs_demo.txt
python3 - <<'PY'
import json, psycopg2
c = psycopg2.connect(dbname="bank_db"); cur = c.cursor()
roles = ["role_client", "role_employee", "role_manager", "role_admin", "role_auditor"]
tables = ["customer", "account", "bank_transaction", "transfer", "beneficiary", "loan", "employee",
          "app_user", "audit_log", "login_attempt", "security_alert", "security_rule",
          "v_customer_masked", "v_account_masked", "v_audit_log_limited"]
M = {}
for t in tables:
    row = {}
    for r in roles:
        s = ""
        for p, ch in (("SELECT", "S"), ("INSERT", "I"), ("UPDATE", "U"), ("DELETE", "D")):
            cur.execute("SELECT has_table_privilege(%s, %s, %s)", (r, "bank." + t, p))
            if cur.fetchone()[0]: s += ch
            elif p != "DELETE":
                cur.execute("SELECT has_any_column_privilege(%s, %s, %s)", (r, "bank." + t, p))
                if cur.fetchone()[0]: s += ch.lower()
        row[r] = s or "-"
    M[t] = row
F = {}
for fn in ["transfer_money(integer,character varying,numeric,text,boolean)", "create_customer(character varying,character varying,date,character varying,character varying,character varying,character varying)", "open_account(integer,character varying,character,numeric)", "update_customer_contact(integer,character varying,character varying,character varying)", "reveal_national_id(integer,text)"]:
    F[fn.split("(")[0]] = {r: (lambda: (cur.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')", (r, "bank." + fn)), cur.fetchone()[0])[1])() for r in roles}
json.dump(dict(tables=M, functions=F), open("/home/claude/bank/build/evidence/priv_matrix.json", "w"), indent=1)
print("matrice ok")
PY
