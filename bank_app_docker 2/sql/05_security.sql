-- [[grants]]
SET ROLE bank_owner;

REVOKE ALL ON SCHEMA bank FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA bank FROM PUBLIC;
GRANT USAGE ON SCHEMA bank TO app_backend, role_client, role_employee, role_auditor;
-- (role_manager et role_admin héritent de role_employee)

-- Fonctions d'aide en lecture seule : utilisables par tous les rôles applicatifs
GRANT EXECUTE ON FUNCTION bank.current_customer_id(), bank.current_app_user_id(),
      bank.current_app_role(), bank.current_client_ip(), bank.has_role(TEXT) TO PUBLIC;

-- ===== ROLE_CLIENT : lecture de SES données, aucune écriture directe sur les soldes
GRANT SELECT (customer_id, first_name, last_name, date_of_birth, email, phone,
              address, created_at, status)            ON bank.customer TO role_client;
GRANT SELECT ON bank.account, bank.bank_transaction, bank.transfer, bank.loan TO role_client;
GRANT SELECT, DELETE ON bank.beneficiary TO role_client;
GRANT INSERT (customer_id, name, bank_name, account_number) ON bank.beneficiary TO role_client;
GRANT UPDATE (name, status)                                 ON bank.beneficiary TO role_client;
GRANT EXECUTE ON FUNCTION bank.transfer_money(INTEGER, VARCHAR, NUMERIC, TEXT, BOOLEAN)
      TO role_client, role_manager;                 -- admin hérite de manager

-- ===== ROLE_EMPLOYEE : vues masquées + opérations encadrées par fonctions
GRANT EXECUTE ON FUNCTION
      bank.create_customer(VARCHAR, VARCHAR, DATE, VARCHAR, VARCHAR, VARCHAR, VARCHAR),
      bank.open_account(INTEGER, VARCHAR, CHAR, NUMERIC),
      bank.update_customer_contact(INTEGER, VARCHAR, VARCHAR, VARCHAR) TO role_employee;

-- ===== ROLE_MANAGER : supervision
GRANT SELECT (customer_id, first_name, last_name, date_of_birth, email, phone,
              address, created_at, status) ON bank.customer TO role_manager;
GRANT SELECT ON bank.account, bank.bank_transaction, bank.transfer, bank.loan,
                bank.beneficiary, bank.security_alert TO role_manager;
GRANT UPDATE (status) ON bank.account, bank.loan TO role_manager;
GRANT EXECUTE ON FUNCTION bank.reveal_national_id(INTEGER, TEXT) TO role_manager;
GRANT INSERT (customer_id, amount, interest_rate, start_date, end_date)
      ON bank.loan TO role_manager;

-- ===== ROLE_ADMIN : gestion des utilisateurs (jamais de DELETE sur les journaux)
GRANT SELECT (user_id, username, role_id, customer_id, employee_id, is_active,
              failed_attempts, locked_until, last_login, created_at) ON bank.app_user TO role_admin;
GRANT INSERT (username, password_hash, role_id, customer_id, employee_id) ON bank.app_user TO role_admin;
GRANT UPDATE (role_id, is_active, password_hash, failed_attempts, locked_until)
      ON bank.app_user TO role_admin;
GRANT SELECT, INSERT, UPDATE ON bank.employee, bank.branch TO role_admin;
GRANT SELECT ON bank.role, bank.audit_log, bank.login_attempt, bank.security_rule TO role_admin;
GRANT UPDATE (threshold, window_minutes, enabled) ON bank.security_rule TO role_admin;
GRANT UPDATE (status) ON bank.security_alert TO role_admin;

-- ===== ROLE_AUDITOR : lecture seule des traces
GRANT SELECT ON bank.audit_log, bank.login_attempt, bank.security_alert,
                bank.security_rule TO role_auditor;

-- ===== Compte technique du backend : uniquement ce qu'il faut pour l'authentification
GRANT SELECT (user_id, username, password_hash, role_id, customer_id, employee_id,
              is_active, locked_until) ON bank.app_user TO app_backend;
GRANT SELECT ON bank.role TO app_backend;
-- Nom affiché ("Bonjour, Amine") : fonction dédiée plutôt qu'un GRANT direct sur
-- customer/employee, qui resteraient de toute façon invisibles à app_backend à
-- cause de leur Row-Level Security (voir bank.get_display_name, 03_functions.sql).
GRANT EXECUTE ON FUNCTION bank.get_display_name(VARCHAR) TO app_backend;
GRANT EXECUTE ON FUNCTION bank.record_login_attempt(VARCHAR, BOOLEAN, INET) TO app_backend;
-- [[/grants]]

-- [[views]]
-- Vues sécurisées : masquage des données sensibles + filtrage par rôle
CREATE VIEW bank.v_customer_masked WITH (security_barrier = true) AS
SELECT c.customer_id, c.first_name, c.last_name,
       regexp_replace(c.email, '^(.).*(@.*)$', '\1***\2')                     AS email_masked,
       left(c.phone, 5) || repeat('*', length(c.phone) - 7) || right(c.phone, 2) AS phone_masked,
       repeat('*', 8) || c.national_id_last4                                   AS national_id_masked,
       c.status, c.created_at
  FROM bank.customer c
 WHERE bank.has_role('role_employee') OR bank.has_role('role_auditor');

CREATE VIEW bank.v_account_masked WITH (security_barrier = true) AS
SELECT a.account_id, a.customer_id,
       left(a.account_number, 4) || repeat('*', length(a.account_number) - 8)
           || right(a.account_number, 4)                                       AS account_number_masked,
       a.account_type, a.balance, a.currency, a.status
  FROM bank.account a
 WHERE bank.has_role('role_employee') OR bank.has_role('role_auditor');

CREATE VIEW bank.v_audit_log_limited WITH (security_barrier = true) AS
SELECT audit_id, timestamp, user_id, action, table_name, record_id, result
  FROM bank.audit_log
 WHERE bank.has_role('role_manager') AND timestamp > now() - interval '30 days';

CREATE VIEW bank.v_balance_reconciliation WITH (security_barrier = true) AS
SELECT a.account_id, a.balance AS balance_account,
       COALESCE(SUM(CASE WHEN t.transaction_type IN ('DEPOSIT','TRANSFER_IN') THEN t.amount
                         ELSE -t.amount END), 0)                               AS balance_ledger,
       a.balance - COALESCE(SUM(CASE WHEN t.transaction_type IN ('DEPOSIT','TRANSFER_IN')
                                     THEN t.amount ELSE -t.amount END), 0)     AS gap
  FROM bank.account a
  LEFT JOIN bank.bank_transaction t ON t.account_id = a.account_id AND t.status = 'COMPLETED'
 WHERE bank.has_role('role_manager') OR bank.has_role('role_auditor')
 GROUP BY a.account_id, a.balance;

GRANT SELECT ON bank.v_customer_masked, bank.v_account_masked TO role_employee, role_auditor;
GRANT SELECT ON bank.v_audit_log_limited TO role_manager;
GRANT SELECT ON bank.v_balance_reconciliation TO role_manager, role_auditor;
-- [[/views]]

-- [[rls]]
ALTER TABLE bank.customer         ENABLE ROW LEVEL SECURITY;
ALTER TABLE bank.account          ENABLE ROW LEVEL SECURITY;
ALTER TABLE bank.bank_transaction ENABLE ROW LEVEL SECURITY;
ALTER TABLE bank.transfer         ENABLE ROW LEVEL SECURITY;
ALTER TABLE bank.loan             ENABLE ROW LEVEL SECURITY;
ALTER TABLE bank.beneficiary      ENABLE ROW LEVEL SECURITY;

-- Client : uniquement les lignes dont il est propriétaire
CREATE POLICY customer_self ON bank.customer FOR SELECT TO role_client
    USING (customer_id = bank.current_customer_id());
CREATE POLICY account_self ON bank.account FOR SELECT TO role_client
    USING (customer_id = bank.current_customer_id());
CREATE POLICY txn_self ON bank.bank_transaction FOR SELECT TO role_client
    USING (account_id IN (SELECT account_id FROM bank.account
                           WHERE customer_id = bank.current_customer_id()));
CREATE POLICY transfer_self ON bank.transfer FOR SELECT TO role_client
    USING (sender_account_id IN (SELECT account_id FROM bank.account
                                  WHERE customer_id = bank.current_customer_id())
        OR receiver_account_id IN (SELECT account_id FROM bank.account
                                    WHERE customer_id = bank.current_customer_id()));
CREATE POLICY loan_self ON bank.loan FOR SELECT TO role_client
    USING (customer_id = bank.current_customer_id());
CREATE POLICY beneficiary_self ON bank.beneficiary FOR ALL TO role_client
    USING (customer_id = bank.current_customer_id())
    WITH CHECK (customer_id = bank.current_customer_id());

-- Manager (et admin par héritage) : supervision de toutes les lignes
CREATE POLICY customer_staff    ON bank.customer         FOR SELECT TO role_manager USING (true);
CREATE POLICY account_staff     ON bank.account          FOR SELECT TO role_manager USING (true);
CREATE POLICY account_staff_upd ON bank.account          FOR UPDATE TO role_manager
    USING (true) WITH CHECK (true);
CREATE POLICY txn_staff         ON bank.bank_transaction FOR SELECT TO role_manager USING (true);
CREATE POLICY transfer_staff    ON bank.transfer         FOR SELECT TO role_manager USING (true);
CREATE POLICY loan_staff        ON bank.loan             FOR SELECT TO role_manager USING (true);
CREATE POLICY loan_staff_write  ON bank.loan             FOR INSERT TO role_manager WITH CHECK (true);
CREATE POLICY loan_staff_upd    ON bank.loan             FOR UPDATE TO role_manager
    USING (true) WITH CHECK (true);
CREATE POLICY beneficiary_staff ON bank.beneficiary      FOR SELECT TO role_manager USING (true);
-- Sans politique applicable : aucune ligne n'est visible (refus par défaut)
RESET ROLE;
-- [[/rls]]
