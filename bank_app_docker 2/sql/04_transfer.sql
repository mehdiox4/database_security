-- [[transfer_money]]
SET ROLE bank_owner;
SET search_path = bank, public;

CREATE FUNCTION bank.transfer_money(
    p_sender_account_id       INTEGER,
    p_receiver_account_number VARCHAR,
    p_amount                  NUMERIC,
    p_description             TEXT    DEFAULT 'Virement',
    p_simulate_failure        BOOLEAN DEFAULT FALSE)   -- uniquement pour les tests
RETURNS TABLE (result_status TEXT, result_message TEXT, result_transfer_id INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bank AS $$
DECLARE
    v_role        TEXT    := bank.current_app_role();
    v_customer    INTEGER := bank.current_customer_id();
    v_receiver_id INTEGER;
    v_sender      bank.account%ROWTYPE;
    v_receiver    bank.account%ROWTYPE;
    v_new_sender  NUMERIC;
    v_new_recv    NUMERIC;
    v_transfer_id INTEGER;
    v_reason      TEXT;
BEGIN
  BEGIN   -- sous-transaction : toute erreur annule uniquement ce bloc (ROLLBACK implicite)
    -- 0. Autorisation de l'appelant
    IF v_role = 'ROLE_CLIENT' THEN
        IF v_customer IS NULL THEN
            RAISE EXCEPTION 'Contexte client absent' USING ERRCODE = 'BK001';
        END IF;
    ELSIF v_role NOT IN ('ROLE_MANAGER', 'ROLE_ADMIN') OR v_role IS NULL THEN
        RAISE EXCEPTION 'Rôle non autorisé à effectuer un virement' USING ERRCODE = 'BK001';
    END IF;

    -- 1. Vérifier le montant
    IF p_amount IS NULL OR p_amount <= 0 OR scale(p_amount) > 2 THEN
        RAISE EXCEPTION 'Montant invalide' USING ERRCODE = 'BK001';
    END IF;

    -- 2. Verrouiller les deux comptes dans un ordre déterministe (anti-deadlock)
    SELECT account_id INTO v_receiver_id FROM bank.account
     WHERE account_number = p_receiver_account_number;
    IF v_receiver_id IS NULL THEN
        RAISE EXCEPTION 'Compte destinataire introuvable' USING ERRCODE = 'BK001';
    END IF;
    IF v_receiver_id = p_sender_account_id THEN
        RAISE EXCEPTION 'Compte source et destination identiques' USING ERRCODE = 'BK001';
    END IF;
    PERFORM 1 FROM bank.account
     WHERE account_id IN (p_sender_account_id, v_receiver_id)
     ORDER BY account_id FOR UPDATE;

    -- 3. Vérifier le compte source
    SELECT * INTO v_sender FROM bank.account WHERE account_id = p_sender_account_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Compte source introuvable' USING ERRCODE = 'BK001';
    END IF;
    IF v_role = 'ROLE_CLIENT' AND v_sender.customer_id <> v_customer THEN
        RAISE EXCEPTION 'Ce compte ne vous appartient pas' USING ERRCODE = 'BK001';
    END IF;
    IF v_sender.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Compte source non actif (%)', v_sender.status USING ERRCODE = 'BK001';
    END IF;

    -- 4. Vérifier le compte destination
    SELECT * INTO v_receiver FROM bank.account WHERE account_id = v_receiver_id;
    IF v_receiver.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Compte destinataire non actif (%)', v_receiver.status
              USING ERRCODE = 'BK001';
    END IF;
    IF v_sender.currency <> v_receiver.currency THEN
        RAISE EXCEPTION 'Devises différentes : virement refusé' USING ERRCODE = 'BK001';
    END IF;
    IF v_role = 'ROLE_CLIENT' AND v_receiver.customer_id <> v_customer
       AND NOT EXISTS (SELECT 1 FROM bank.beneficiary b
                        WHERE b.customer_id = v_customer
                          AND b.account_number = p_receiver_account_number
                          AND b.status = 'ACTIVE') THEN
        RAISE EXCEPTION 'Destinataire absent de vos bénéficiaires actifs' USING ERRCODE = 'BK001';
    END IF;

    -- 5. Vérifier le solde
    IF v_sender.balance < p_amount THEN
        RAISE EXCEPTION 'Solde insuffisant (% MAD disponible)', v_sender.balance
              USING ERRCODE = 'BK001';
    END IF;

    -- 6. Enregistrer le virement (déclenche audit + règles de détection)
    INSERT INTO bank.transfer (sender_account_id, receiver_account_id, amount, status)
    VALUES (v_sender.account_id, v_receiver.account_id, p_amount, 'COMPLETED')
    RETURNING transfer_id INTO v_transfer_id;

    -- 7. Débiter la source (le garde-fou n'autorise que ce contexte précis)
    PERFORM set_config('bank.balance_op', 'TRANSFER', true);
    UPDATE bank.account SET balance = balance - p_amount
     WHERE account_id = v_sender.account_id RETURNING balance INTO v_new_sender;

    IF p_simulate_failure THEN
        RAISE EXCEPTION 'Panne simulée après le débit' USING ERRCODE = 'BK999';
    END IF;

    -- 8. Créditer la destination
    UPDATE bank.account SET balance = balance + p_amount
     WHERE account_id = v_receiver.account_id RETURNING balance INTO v_new_recv;
    PERFORM set_config('bank.balance_op', '', true);

    -- 9. Écritures comptables (journal en ajout seul)
    INSERT INTO bank.bank_transaction
           (account_id, transfer_id, transaction_type, amount, balance_after, description)
    VALUES (v_sender.account_id,   v_transfer_id, 'TRANSFER_OUT', p_amount, v_new_sender, p_description),
           (v_receiver.account_id, v_transfer_id, 'TRANSFER_IN',  p_amount, v_new_recv,   p_description);

    RETURN QUERY SELECT 'COMPLETED'::TEXT, 'Virement exécuté'::TEXT, v_transfer_id;

  EXCEPTION
    WHEN SQLSTATE 'BK001' THEN          -- règle métier violée : rien n'a été modifié
        GET STACKED DIAGNOSTICS v_reason = MESSAGE_TEXT;
        INSERT INTO bank.audit_log (user_id, action, table_name, record_id, ip_address,
                                    new_value, result)
        VALUES (bank.current_app_user_id(), 'TRANSFER_REJECTED', 'account', p_sender_account_id,
                bank.current_client_ip(),
                jsonb_build_object('amount', p_amount, 'receiver', p_receiver_account_number,
                                   'reason', v_reason), 'REJECTED');
        RETURN QUERY SELECT 'REJECTED'::TEXT, v_reason, NULL::INTEGER;
    WHEN OTHERS THEN                    -- erreur technique : ROLLBACK du bloc déjà effectué
        GET STACKED DIAGNOSTICS v_reason = MESSAGE_TEXT;
        INSERT INTO bank.audit_log (user_id, action, table_name, record_id, ip_address,
                                    new_value, result)
        VALUES (bank.current_app_user_id(), 'TRANSFER_ROLLBACK', 'account', p_sender_account_id,
                bank.current_client_ip(),
                jsonb_build_object('amount', p_amount, 'receiver', p_receiver_account_number,
                                   'reason', v_reason, 'sqlstate', SQLSTATE), 'FAILED');
        RETURN QUERY SELECT 'ROLLED_BACK'::TEXT, v_reason, NULL::INTEGER;
  END;
END $$;
-- [[/transfer_money]]
RESET ROLE;
