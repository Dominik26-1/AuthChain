-- Vymazanie všetkých tabuliek v danej databáze
DROP TABLE IF EXISTS AuthBlocks CASCADE;
DROP TABLE IF EXISTS AuthTransactions CASCADE;
DROP TABLE IF EXISTS Certificates CASCADE;
DROP TABLE IF EXISTS PaymentBlocks CASCADE;
DROP TABLE IF EXISTS PaymentTransactions CASCADE;
-- a tak ďalej pre všetky tabuľky, ktoré chcete vymazať
