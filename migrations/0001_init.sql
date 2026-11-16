-- Calls from allowlisted peers waiting for the background worker.
CREATE TABLE inbox (
    -- AUTOINCREMENT keeps ids from being reused after a row is deleted.
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Sender's peer id, as authenticated by TLS.
    peer        TEXT    NOT NULL,
    -- JSON-serialized Request::Command.
    payload     TEXT    NOT NULL,
    received_at INTEGER NOT NULL DEFAULT (unixepoch())
);
