-- Shares this node holds. The share value is only stored sealed to the share public key (HPKE,
-- see SealedShare); sender, share_id and name are bound into the ciphertext as associated data
-- and must stay exactly as received, or the share no longer opens.
CREATE TABLE shares (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Share.id. A node holds one share per id: the first one received is kept, so a peer cannot
    -- replace a share another dealer sent.
    share_id    TEXT    NOT NULL UNIQUE,
    -- Share.from as sent; not authenticated.
    sender      TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    -- Peer id that delivered the share, as authenticated by TLS.
    peer        TEXT    NOT NULL,
    -- HPKE encapsulated key and ciphertext of the big-endian share value.
    enc         BLOB    NOT NULL,
    ciphertext  BLOB    NOT NULL,
    received_at INTEGER NOT NULL
);
