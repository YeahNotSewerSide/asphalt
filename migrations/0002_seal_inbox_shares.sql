-- Inbox payloads are now InboxEntry JSON, where a new share is sealed to the share public key.
-- Remove rows in the earlier Request JSON format, which held shares in plaintext, and have
-- SQLite zero the freed pages instead of leaving the old bytes in the file.
PRAGMA secure_delete = ON;
DELETE FROM inbox WHERE payload LIKE '{"Command":%';
