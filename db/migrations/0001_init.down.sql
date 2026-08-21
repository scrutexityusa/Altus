-- Reverses 0001_init by dropping the schema entirely.
--
-- This destroys every authorization decision, approval and evidence receipt in
-- the database. It exists so the migration history is genuinely reversible in
-- development and in disposable test databases. There is no scenario in which
-- running it against production is correct: evidence is meant to outlive the
-- code that produced it.
DROP SCHEMA IF EXISTS scrutexity CASCADE;
