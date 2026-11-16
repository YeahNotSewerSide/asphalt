-- Requests for a share. A request is approved by a client that proves it holds this node's share
-- secret key; that client re-seals the share to the requester's reply_key.
CREATE TABLE share_requests (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Requesting client's peer id, as authenticated by TLS.
    requester           TEXT    NOT NULL,
    share_id            TEXT    NOT NULL REFERENCES shares (share_id),
    -- Share public key the approver re-seals the share to.
    reply_key           BLOB    NOT NULL,
    status              TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved')),
    requested_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    approved_by         TEXT,
    approved_at         INTEGER,
    -- The share re-sealed to reply_key; it opens only with the requester's share secret key.
    delivery_enc        BLOB,
    delivery_ciphertext BLOB
);

-- At most one pending request per requester and share; asking again refreshes it.
CREATE UNIQUE INDEX share_requests_pending ON share_requests (requester, share_id)
    WHERE status = 'pending';
