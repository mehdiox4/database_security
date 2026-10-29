-- [[helpers]]
SET ROLE bank_owner;
SET search_path = bank, public;

-- Contexte applicatif : le backend l'initialise après authentification
CREATE FUNCTION bank.current_customer_id() RETURNS INTEGER
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.customer_id', true), '')::INTEGER $$;

CREATE FUNCTION bank.current_app_user_id() RETURNS INTEGER
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::INTEGER $$;

CREATE FUNCTION bank.current_app_role() RETURNS TEXT
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.role', true), '') $$;

CREATE FUNCTION bank.current_client_ip() RETURNS INET
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.ip', true), '')::INET $$;

-- Vrai si le rôle PostgreSQL courant possède les privilèges du rôle demandé
CREATE FUNCTION bank.has_role(p_role TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$ SELECT pg_has_role(current_user, p_role, 'USAGE') $$;
-- [[/helpers]]

-- [[fn_audit]]
-- Trigger générique d'audit : enregistre uniquement les champs modifiés.
-- Arguments : TG_ARGV[0] = nom de la clé primaire, TG_ARGV[1] = champs à ne jamais journaliser
CREATE FUNCTION bank.fn_audit_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
DECLARE
    v_pk     TEXT   := TG_ARGV[0];
    v_strip  TEXT[] := string_to_array(COALESCE(TG_ARGV[1], ''), ',');
    v_old    JSONB;
    v_new    JSONB;
    v_old_d  JSONB;
    v_new_d  JSONB;
    v_id     BIGINT;
    v_result TEXT := 'SUCCESS';
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN v_old := to_jsonb(OLD) - v_strip; END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN v_new := to_jsonb(NEW) - v_strip; END IF;
    v_id := COALESCE(v_new ->> v_pk, v_old ->> v_pk)::BIGINT;

    IF TG_OP = 'UPDATE' THEN                       -- ne garder que les colonnes modifiées
        SELECT jsonb_object_agg(n.key, n.value), jsonb_object_agg(n.key, v_old -> n.key)
          INTO v_new_d, v_old_d
          FROM jsonb_each(v_new) AS n
         WHERE (v_old -> n.key) IS DISTINCT FROM n.value;
        IF v_new_d IS NULL THEN RETURN NULL; END IF;   -- aucune modification réelle
        v_old := v_old_d;
        v_new := v_new_d;
    END IF;

    IF TG_TABLE_NAME = 'security_alert' THEN v_result := 'ALERT'; END IF;

    INSERT INTO bank.audit_log
           (user_id, action, table_name, record_id, ip_address, old_value, new_value, result)
    VALUES (bank.current_app_user_id(), TG_OP, TG_TABLE_NAME, v_id,
            bank.current_client_ip(), v_old, v_new, v_result);
    RETURN NULL;
END $$;
-- [[/fn_audit]]

-- [[fn_guards]]
-- Garde-fou 1 : le solde ne peut être modifié que par transfer_money()
CREATE FUNCTION bank.fn_account_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, bank AS $$
BEGIN
    IF NEW.balance IS DISTINCT FROM OLD.balance
       AND COALESCE(current_setting('bank.balance_op', true), '') <> 'TRANSFER' THEN
        RAISE EXCEPTION 'Modification directe du solde interdite (compte %)', OLD.account_id
              USING ERRCODE = 'BK002';
    END IF;
    IF NEW.account_number <> OLD.account_number OR NEW.customer_id <> OLD.customer_id THEN
        RAISE EXCEPTION 'Numéro de compte et titulaire sont immuables (compte %)', OLD.account_id
              USING ERRCODE = 'BK002';
    END IF;
    RETURN NEW;
END $$;

-- Garde-fou 2 : tables en écriture seule (journal comptable, audit, connexions)
CREATE FUNCTION bank.fn_block_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Table % en ajout seul : % interdit', TG_TABLE_NAME, TG_OP
          USING ERRCODE = 'BK003';
END $$;
-- [[/fn_guards]]

-- [[fn_detection]]
-- Règles 1 et 2 : virements rapides / montant élevé
CREATE FUNCTION bank.fn_transfer_fraud_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
DECLARE
    v_rule  bank.security_rule%ROWTYPE;
    v_count INTEGER;
BEGIN
    SELECT * INTO v_rule FROM bank.security_rule WHERE rule_code = 'RAPID_TRANSFERS' AND enabled;
    IF FOUND THEN
        SELECT count(*) INTO v_count FROM bank.transfer
         WHERE sender_account_id = NEW.sender_account_id
           AND transfer_date >= now() - make_interval(mins => v_rule.window_minutes);
        IF v_count >= v_rule.threshold AND NOT EXISTS (          -- une seule alerte par fenêtre
               SELECT 1 FROM bank.security_alert
                WHERE rule_code = 'RAPID_TRANSFERS' AND account_id = NEW.sender_account_id
                  AND created_at >= now() - make_interval(mins => v_rule.window_minutes)) THEN
            INSERT INTO bank.security_alert (rule_code, severity, account_id, description)
            VALUES ('RAPID_TRANSFERS', 'HIGH', NEW.sender_account_id,
                    format('%s virements en %s min depuis le compte %s',
                           v_count, v_rule.window_minutes, NEW.sender_account_id));
        END IF;
    END IF;

    SELECT * INTO v_rule FROM bank.security_rule WHERE rule_code = 'LARGE_TRANSFER' AND enabled;
    IF FOUND AND NEW.amount >= v_rule.threshold THEN
        INSERT INTO bank.security_alert (rule_code, severity, account_id, description)
        VALUES ('LARGE_TRANSFER', 'MEDIUM', NEW.sender_account_id,
                format('Virement de %s MAD (seuil %s) depuis le compte %s',
                       NEW.amount, v_rule.threshold, NEW.sender_account_id));
    END IF;
    RETURN NULL;
END $$;

-- Règle 3 : tentatives de connexion répétées => verrouillage + alerte
CREATE FUNCTION bank.fn_login_attempt_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
DECLARE
    v_rule bank.security_rule%ROWTYPE;
    v_fail INTEGER;
BEGIN
    IF NEW.success THEN
        UPDATE bank.app_user SET failed_attempts = 0, last_login = now()
         WHERE username = NEW.username;
        RETURN NULL;
    END IF;

    UPDATE bank.app_user SET failed_attempts = failed_attempts + 1 WHERE username = NEW.username;
    SELECT * INTO v_rule FROM bank.security_rule WHERE rule_code = 'BRUTE_FORCE' AND enabled;
    IF FOUND THEN
        SELECT count(*) INTO v_fail FROM bank.login_attempt
         WHERE username = NEW.username AND NOT success
           AND attempted_at >= now() - make_interval(mins => v_rule.window_minutes);
        IF v_fail >= v_rule.threshold THEN
            UPDATE bank.app_user SET locked_until = now() + interval '15 minutes'
             WHERE username = NEW.username AND (locked_until IS NULL OR locked_until < now());
            IF FOUND THEN
                INSERT INTO bank.security_alert (rule_code, severity, username, description)
                VALUES ('BRUTE_FORCE', 'CRITICAL', NEW.username,
                        format('%s échecs de connexion en %s min : compte %s verrouillé 15 min',
                               v_fail, v_rule.window_minutes, NEW.username));
            END IF;
        END IF;
    END IF;
    RETURN NULL;
END $$;

-- Règle 4 : modifications répétées d'un compte (hors solde)
CREATE FUNCTION bank.fn_account_modcheck() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
DECLARE
    v_rule  bank.security_rule%ROWTYPE;
    v_count INTEGER;
BEGIN
    SELECT * INTO v_rule FROM bank.security_rule WHERE rule_code = 'ACCOUNT_CHANGES' AND enabled;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT count(*) INTO v_count FROM bank.audit_log
     WHERE table_name = 'account' AND record_id = NEW.account_id AND action = 'UPDATE'
       AND NOT (new_value ? 'balance')
       AND timestamp >= now() - make_interval(mins => v_rule.window_minutes);
    IF v_count >= v_rule.threshold AND NOT EXISTS (
           SELECT 1 FROM bank.security_alert
            WHERE rule_code = 'ACCOUNT_CHANGES' AND account_id = NEW.account_id
              AND created_at >= now() - make_interval(mins => v_rule.window_minutes)) THEN
        INSERT INTO bank.security_alert (rule_code, severity, account_id, description)
        VALUES ('ACCOUNT_CHANGES', 'MEDIUM', NEW.account_id,
                format('%s modifications du compte %s en %s min',
                       v_count, NEW.account_id, v_rule.window_minutes));
    END IF;
    RETURN NULL;
END $$;
-- [[/fn_detection]]

-- [[triggers]]
-- Audit automatique (INSERT / UPDATE / DELETE)
CREATE TRIGGER trg_customer_audit AFTER INSERT OR UPDATE OR DELETE ON bank.customer
    FOR EACH ROW EXECUTE FUNCTION bank.fn_audit_row('customer_id', 'national_id,national_id_hash');
CREATE TRIGGER trg_account_audit AFTER INSERT OR UPDATE OR DELETE ON bank.account
    FOR EACH ROW EXECUTE FUNCTION bank.fn_audit_row('account_id', '');
CREATE TRIGGER trg_transfer_audit AFTER INSERT ON bank.transfer
    FOR EACH ROW EXECUTE FUNCTION bank.fn_audit_row('transfer_id', '');
CREATE TRIGGER trg_loan_audit AFTER INSERT OR UPDATE OR DELETE ON bank.loan
    FOR EACH ROW EXECUTE FUNCTION bank.fn_audit_row('loan_id', '');
CREATE TRIGGER trg_beneficiary_audit AFTER INSERT OR UPDATE OR DELETE ON bank.beneficiary
    FOR EACH ROW EXECUTE FUNCTION bank.fn_audit_row('beneficiary_id', '');
CREATE TRIGGER trg_alert_audit AFTER INSERT ON bank.security_alert
    FOR EACH ROW EXECUTE FUNCTION bank.fn_audit_row('alert_id', '');
CREATE TRIGGER trg_user_audit_ins_del AFTER INSERT OR DELETE ON bank.app_user
    FOR EACH ROW EXECUTE FUNCTION bank.fn_audit_row('user_id', 'password_hash');
CREATE TRIGGER trg_user_audit_upd AFTER UPDATE ON bank.app_user
    FOR EACH ROW
    WHEN (OLD.role_id IS DISTINCT FROM NEW.role_id
          OR OLD.is_active IS DISTINCT FROM NEW.is_active
          OR OLD.password_hash IS DISTINCT FROM NEW.password_hash)
    EXECUTE FUNCTION bank.fn_audit_row('user_id', 'password_hash');

-- Garde-fous d'intégrité
CREATE TRIGGER trg_account_guard BEFORE UPDATE ON bank.account
    FOR EACH ROW EXECUTE FUNCTION bank.fn_account_guard();
CREATE TRIGGER trg_txn_readonly BEFORE UPDATE OR DELETE ON bank.bank_transaction
    FOR EACH ROW EXECUTE FUNCTION bank.fn_block_change();
CREATE TRIGGER trg_txn_notruncate BEFORE TRUNCATE ON bank.bank_transaction
    FOR EACH STATEMENT EXECUTE FUNCTION bank.fn_block_change();
CREATE TRIGGER trg_audit_readonly BEFORE UPDATE OR DELETE ON bank.audit_log
    FOR EACH ROW EXECUTE FUNCTION bank.fn_block_change();
CREATE TRIGGER trg_audit_notruncate BEFORE TRUNCATE ON bank.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION bank.fn_block_change();
CREATE TRIGGER trg_login_readonly BEFORE UPDATE OR DELETE ON bank.login_attempt
    FOR EACH ROW EXECUTE FUNCTION bank.fn_block_change();

-- Détection d'activités suspectes
CREATE TRIGGER trg_transfer_fraud AFTER INSERT ON bank.transfer
    FOR EACH ROW EXECUTE FUNCTION bank.fn_transfer_fraud_check();
CREATE TRIGGER trg_login_check AFTER INSERT ON bank.login_attempt
    FOR EACH ROW EXECUTE FUNCTION bank.fn_login_attempt_check();
CREATE TRIGGER trg_account_modcheck AFTER UPDATE ON bank.account
    FOR EACH ROW WHEN (OLD.balance IS NOT DISTINCT FROM NEW.balance)
    EXECUTE FUNCTION bank.fn_account_modcheck();
-- [[/triggers]]

-- [[fn_staff]]
-- Opérations employé : exécutées avec les droits du propriétaire (SECURITY DEFINER),
-- mais seulement exécutables par role_employee (et rôles hérités).
CREATE FUNCTION bank.create_customer(
    p_first VARCHAR, p_last VARCHAR, p_dob DATE, p_email VARCHAR,
    p_phone VARCHAR, p_address VARCHAR, p_national_id VARCHAR)
RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank, public AS $$
DECLARE
    v_key TEXT := current_setting('app.enc_key', true);   -- fournie par le backend (KMS)
    v_id  INTEGER;
BEGIN
    IF v_key IS NULL OR length(v_key) < 16 THEN
        RAISE EXCEPTION 'Clé de chiffrement absente' USING ERRCODE = 'BK004';
    END IF;
    IF p_dob > CURRENT_DATE - INTERVAL '18 years' THEN
        RAISE EXCEPTION 'Le client doit être majeur' USING ERRCODE = 'BK001';
    END IF;
    INSERT INTO bank.customer (first_name, last_name, date_of_birth, email, phone, address,
                               national_id, national_id_last4, national_id_hash)
    VALUES (p_first, p_last, p_dob, lower(p_email), p_phone, p_address,
            pgp_sym_encrypt(p_national_id, v_key), right(p_national_id, 4),
            hmac(p_national_id, v_key, 'sha256'))
    RETURNING customer_id INTO v_id;
    RETURN v_id;
END $$;

CREATE FUNCTION bank.open_account(
    p_customer_id INTEGER, p_type VARCHAR, p_currency CHAR DEFAULT 'MAD',
    p_initial_deposit NUMERIC DEFAULT 0)
RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
DECLARE v_id INTEGER;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM bank.customer WHERE customer_id = p_customer_id
                                                 AND status = 'ACTIVE') THEN
        RAISE EXCEPTION 'Client inexistant ou non actif' USING ERRCODE = 'BK001';
    END IF;
    INSERT INTO bank.account (customer_id, account_type, currency, balance)
    VALUES (p_customer_id, p_type, p_currency, p_initial_deposit)
    RETURNING account_id INTO v_id;
    IF p_initial_deposit > 0 THEN
        INSERT INTO bank.bank_transaction
               (account_id, transaction_type, amount, balance_after, description)
        VALUES (v_id, 'DEPOSIT', p_initial_deposit, p_initial_deposit, 'Dépôt initial');
    END IF;
    RETURN v_id;
END $$;

CREATE FUNCTION bank.update_customer_contact(
    p_customer_id INTEGER, p_email VARCHAR DEFAULT NULL,
    p_phone VARCHAR DEFAULT NULL, p_address VARCHAR DEFAULT NULL)
RETURNS VOID
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
    UPDATE bank.customer
       SET email   = COALESCE(lower(p_email), email),
           phone   = COALESCE(p_phone, phone),
           address = COALESCE(p_address, address)
     WHERE customer_id = p_customer_id;
$$;

CREATE FUNCTION bank.record_login_attempt(p_username VARCHAR, p_success BOOLEAN, p_ip INET)
RETURNS VOID
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
    INSERT INTO bank.login_attempt (username, success, ip_address)
    VALUES (p_username, p_success, p_ip);
$$;
-- [[/fn_staff]]

-- [[fn_display_name]]
-- Nom affiché après connexion ("Bonjour, Amine"). Fonction dédiée plutôt qu'un
-- GRANT direct sur customer/employee pour app_backend : customer et employee
-- sont protégées par Row-Level Security, à laquelle app_backend (compte
-- technique, sans rôle métier avant SET LOCAL ROLE) n'est partie à aucune
-- politique. SECURITY DEFINER exécute cette requête avec les droits du
-- propriétaire des tables (bank_owner), qui n'est pas soumis à leur RLS, mais
-- la fonction ne renvoie que deux colonnes non sensibles pour un seul compte.
CREATE FUNCTION bank.get_display_name(p_username VARCHAR)
RETURNS TABLE(first_name VARCHAR, last_name VARCHAR)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
    SELECT COALESCE(c.first_name, e.first_name), COALESCE(c.last_name, e.last_name)
      FROM bank.app_user u
      LEFT JOIN bank.customer c ON c.customer_id = u.customer_id
      LEFT JOIN bank.employee e ON e.employee_id = u.employee_id
     WHERE u.username = p_username;
$$;
-- [[/fn_display_name]]

-- [[fn_sensitive]]
-- Lecture du numéro d'identité en clair : motif obligatoire + trace READ_SENSITIVE
CREATE FUNCTION bank.reveal_national_id(p_customer_id INTEGER, p_reason TEXT)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank, public AS $$
DECLARE
    v_key TEXT := current_setting('app.enc_key', true);
    v_val TEXT;
BEGIN
    IF p_reason IS NULL OR length(trim(p_reason)) < 10 THEN
        RAISE EXCEPTION 'Motif obligatoire (10 caractères minimum)' USING ERRCODE = 'BK001';
    END IF;
    SELECT pgp_sym_decrypt(national_id, v_key) INTO v_val
      FROM bank.customer WHERE customer_id = p_customer_id;
    INSERT INTO bank.audit_log (user_id, action, table_name, record_id, ip_address,
                                new_value, result)
    VALUES (bank.current_app_user_id(), 'READ_SENSITIVE', 'customer', p_customer_id,
            bank.current_client_ip(),
            jsonb_build_object('field', 'national_id', 'reason', p_reason), 'SUCCESS');
    RETURN v_val;
END $$;
-- [[/fn_sensitive]]
