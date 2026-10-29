CREATE TEMP TABLE demo_account (
    name    text PRIMARY KEY,
    balance numeric(12,2) NOT NULL CHECK (balance >= 0));
INSERT INTO demo_account VALUES ('A', 1000), ('B', 500);
SELECT * FROM demo_account ORDER BY name;

-- Scénario 1 : virement de 300 DH réussi
BEGIN;
UPDATE demo_account SET balance = balance - 300 WHERE name = 'A';
UPDATE demo_account SET balance = balance + 300 WHERE name = 'B';
COMMIT;
SELECT * FROM demo_account ORDER BY name;

-- Retour à l'état initial puis scénario 2 : erreur pendant l'opération
UPDATE demo_account SET balance = CASE name WHEN 'A' THEN 1000 ELSE 500 END;
BEGIN;
UPDATE demo_account SET balance = balance - 300 WHERE name = 'A';
SELECT * FROM demo_account ORDER BY name;
UPDATE demo_account SET balance = balance + 300 / 0 WHERE name = 'B';
UPDATE demo_account SET balance = balance + 300 WHERE name = 'B';
ROLLBACK;
SELECT * FROM demo_account ORDER BY name;

-- Cohérence : un solde négatif est refusé par la contrainte CHECK
UPDATE demo_account SET balance = balance - 5000 WHERE name = 'A';
