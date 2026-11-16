//! The node: stores shares sealed by dealers, records share requests, and releases a share once
//! the client holding this node's share key approves the request.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use futures::StreamExt as _;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    multiaddr::Protocol,
    ping, request_response,
    swarm::{
        DialError, SwarmEvent,
        dial_opts::{DialOpts, PeerCondition},
    },
};
use serde::{Deserialize, Serialize};
use sqlx::{
    SqliteConnection, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tokio::{select, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    AwaitingApproval, AwaitingResponse, Command, Request, Response, RpcError, ShareInfo,
    crypto::{self, SealedShare, SharePublicKey},
    keys,
    net::{self, BehaviourEvent, RpcReply},
};

const REDIAL_INTERVAL: Duration = Duration::from_secs(10);
/// How long a request can wait for approval, in seconds. An expired request is refused, then
/// deleted.
const REQUEST_TTL_SECS: i64 = 5 * 60;
/// How long the requester can fetch an approved share, in seconds. The request is deleted after.
const APPROVAL_TTL_SECS: i64 = 5 * 60;
/// How long an approver has to answer a challenge. A challenge never outlives its request.
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
/// How often expired requests and challenges are removed.
const PRUNE_INTERVAL: Duration = Duration::from_secs(30);
/// Most rows one list call returns.
const MAX_PAGE: u32 = 100;

pub struct Options {
    pub key: PathBuf,
    pub db: PathBuf,
    pub share_pubkey: PathBuf,
    pub listen: Multiaddr,
    pub allownodes: Vec<PeerId>,
    pub allowclients: Vec<PeerId>,
    pub connect: Vec<Multiaddr>,
}

pub async fn run(opts: Options) -> anyhow::Result<()> {
    let targets = opts
        .connect
        .into_iter()
        .map(dial_target)
        .collect::<anyhow::Result<Vec<_>>>()?;
    if let Some((peer, _)) = targets
        .iter()
        .find(|(peer, _)| !opts.allownodes.contains(peer))
    {
        anyhow::bail!("--connect peer {peer} is not in --allownodes");
    }
    let share_key = keys::load_share_public_key(&opts.share_pubkey)?;

    // Cancelling this token stops the node: the main loop and the inbox worker watch it.
    let shutdown = CancellationToken::new();
    let signal = shutdown_signal()?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            signal.await;
            shutdown.cancel();
        }
    });

    let db = open_db(&opts.db).await?;
    let (worker_tx, worker_rx) = mpsc::unbounded_channel();
    // Rows left from the last run are queued before the swarm can receive new calls.
    let backlog: Vec<i64> = sqlx::query_scalar("SELECT id FROM inbox ORDER BY id")
        .fetch_all(&db)
        .await?;
    if !backlog.is_empty() {
        info!(rows = backlog.len(), "resuming inbox backlog");
    }
    for row_id in backlog {
        worker_tx.send(row_id)?;
    }
    let worker = tokio::spawn(inbox_worker(db.clone(), worker_rx, shutdown.clone()));

    let identity = keys::load_keypair(&opts.key)?;
    let local = identity.public().to_peer_id();
    let allowed = opts.allownodes.iter().chain(&opts.allowclients).copied();
    let mut swarm = net::swarm(identity, allowed, Duration::from_secs(u64::MAX))?;
    let mut state = State {
        inbox: Inbox {
            db,
            worker: worker_tx,
        },
        share_key,
        local,
        clients: opts.allowclients.into_iter().collect(),
        challenges: HashMap::new(),
    };

    info!(
        peer_id = %local,
        nodes = opts.allownodes.len(),
        clients = state.clients.len(),
        "starting node"
    );
    swarm.listen_on(opts.listen)?;

    let mut redial = tokio::time::interval(REDIAL_INTERVAL);
    let mut prune = tokio::time::interval(PRUNE_INTERVAL);
    loop {
        // A call being handled finishes before the token is checked again.
        select! {
            _ = shutdown.cancelled() => break,
            _ = redial.tick() => {
                for (peer, addr) in &targets {
                    let opts = DialOpts::peer_id(*peer)
                        .addresses(vec![addr.clone()])
                        .condition(PeerCondition::DisconnectedAndNotDialing)
                        .build();
                    match swarm.dial(opts) {
                        Ok(()) | Err(DialError::DialPeerConditionFalse(_)) => {}
                        Err(e) => warn!(%peer, "dial failed: {e}"),
                    }
                }
            }
            _ = prune.tick() => prune_expired(&mut state).await,
            event = swarm.select_next_some() => handle_event(&mut swarm, &mut state, event).await,
        }
    }

    info!("shutting down");
    // The worker finishes the row it's on. Rows still queued stay in the inbox and are processed
    // on the next start.
    worker.await?;
    // Closing the pool lets SQLite checkpoint the WAL into the database file.
    state.inbox.db.close().await;
    info!("stopped");
    Ok(())
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM (`systemctl stop`). The handlers are installed here,
/// before the future is first polled, so a signal that arrives while the node is busy isn't lost.
fn shutdown_signal() -> std::io::Result<impl Future<Output = ()>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            select! {
                _ = interrupt.recv() => info!("SIGINT received"),
                _ = terminate.recv() => info!("SIGTERM received"),
            }
        })
    }
    #[cfg(not(unix))]
    {
        let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
        Ok(async move {
            ctrl_c.recv().await;
            info!("Ctrl-C received");
        })
    }
}

/// Splits `/.../p2p/<peer-id>` into the peer id and the address to dial.
fn dial_target(addr: Multiaddr) -> anyhow::Result<(PeerId, Multiaddr)> {
    match addr.iter().last() {
        Some(Protocol::P2p(peer)) => Ok((peer, addr)),
        _ => anyhow::bail!("{addr} must end with /p2p/<peer-id>"),
    }
}

pub async fn open_db(path: &Path) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        // Deleted rows (expired requests, re-sealed shares) are zeroed, not left in free pages.
        .pragma("secure_delete", "on");
    let db = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .with_context(|| format!("failed to open {}", path.display()))?;
    sqlx::migrate!().run(&db).await?;
    Ok(db)
}

struct State {
    inbox: Inbox,
    share_key: SharePublicKey,
    local: PeerId,
    clients: HashSet<PeerId>,
    /// Open approval challenges by request and approver.
    challenges: HashMap<(i64, PeerId), Challenge>,
}

struct Challenge {
    expected: [u8; 32],
    expires: Instant,
}

/// A call as stored in the inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InboxEntry {
    id: u64,
    ts: u64,
    cmd: InboxCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum InboxCommand {
    NewShare(SealedShare),
    RequestShare {
        share_id: String,
        #[serde(with = "hex")]
        reply_key: Vec<u8>,
    },
}

/// Incoming calls waiting for the background worker. Rows are durable; the channel only tells the
/// worker which row id is new.
struct Inbox {
    db: SqlitePool,
    worker: mpsc::UnboundedSender<i64>,
}

impl Inbox {
    async fn push(&self, peer: PeerId, id: u64, ts: u64, cmd: InboxCommand) -> anyhow::Result<i64> {
        let row_id = sqlx::query("INSERT INTO inbox (peer, payload) VALUES (?, ?)")
            .bind(peer.to_string())
            .bind(serde_json::to_string(&InboxEntry { id, ts, cmd })?)
            .execute(&self.db)
            .await?
            .last_insert_rowid();
        self.worker.send(row_id)?;
        Ok(row_id)
    }
}

/// Drops expired challenges and deletes expired requests. Expiry is also checked wherever a
/// request or challenge is used, so this only removes what can no longer be used.
async fn prune_expired(state: &mut State) {
    let now = Instant::now();
    state.challenges.retain(|_, c| c.expires > now);
    match delete_expired_requests(&state.inbox.db).await {
        Ok(0) => {}
        Ok(deleted) => info!(deleted, "expired share requests deleted"),
        Err(e) => error!("failed to delete expired share requests: {e:#}"),
    }
}

/// Deletes pending requests past `REQUEST_TTL_SECS` and approved ones, with their re-sealed
/// share, past `APPROVAL_TTL_SECS`.
async fn delete_expired_requests(db: &SqlitePool) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM share_requests
         WHERE (status = 'pending' AND requested_at <= unixepoch() - ?)
            OR (status = 'approved' AND approved_at <= unixepoch() - ?)",
    )
    .bind(REQUEST_TTL_SECS)
    .bind(APPROVAL_TTL_SECS)
    .execute(db)
    .await?
    .rows_affected())
}

async fn inbox_worker(
    db: SqlitePool,
    mut queued: mpsc::UnboundedReceiver<i64>,
    shutdown: CancellationToken,
) {
    loop {
        let row_id = select! {
            // Shutdown doesn't wait for the queue to drain; queued rows stay in the inbox.
            biased;
            _ = shutdown.cancelled() => break,
            row_id = queued.recv() => row_id,
        };
        let Some(row_id) = row_id else { break };
        if let Err(e) = process_inbox_row(&db, row_id).await {
            error!(row_id, "failed to process inbox row: {e:#}");
        }
    }
}

/// Reads, parses and deletes one inbox row in a single transaction, so an error leaves the row
/// in place for the next start.
async fn process_inbox_row(db: &SqlitePool, row_id: i64) -> anyhow::Result<()> {
    // IMMEDIATE takes the write lock up front. A deferred transaction would fail with
    // SQLITE_BUSY_SNAPSHOT if the rpc handler inserted a row between our SELECT and DELETE.
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;

    let Some((peer, payload, received_at)) = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT peer, payload, received_at FROM inbox WHERE id = ?",
    )
    .bind(row_id)
    .fetch_optional(&mut *tx)
    .await?
    else {
        anyhow::bail!("row not found");
    };
    let peer: PeerId = peer.parse()?;
    let InboxEntry { id, ts, cmd } = serde_json::from_str(&payload)?;

    match cmd {
        InboxCommand::NewShare(share) => {
            if store_share(&mut tx, peer, received_at, &share).await? {
                info!(row_id, %peer, id, ts, share_id = %share.id, name = %share.name, "share stored");
            } else {
                warn!(row_id, %peer, id, ts, share_id = %share.id, "share id already held, keeping the existing share");
            }
        }
        InboxCommand::RequestShare {
            share_id,
            reply_key,
        } => {
            // A request's lifetime starts when the node received it, so one replayed from the
            // inbox after a restart doesn't get a fresh five minutes.
            if received_at <= chrono::Utc::now().timestamp() - REQUEST_TTL_SECS {
                warn!(row_id, %peer, id, ts, %share_id, "share request expired before it was processed");
            } else {
                match store_request(&mut tx, peer, &share_id, &reply_key, received_at).await? {
                    Some(request) => {
                        info!(row_id, %peer, id, ts, request, %share_id, "share requested")
                    }
                    None => warn!(row_id, %peer, id, ts, %share_id, "share requested but not held"),
                }
            }
        }
    }

    sqlx::query("DELETE FROM inbox WHERE id = ?")
        .bind(row_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Stores a sealed share as received, so its metadata still matches the associated data it was
/// sealed with. Returns false if a share with this id is already held; the first one is kept.
async fn store_share(
    tx: &mut SqliteConnection,
    peer: PeerId,
    received_at: i64,
    share: &SealedShare,
) -> anyhow::Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO shares (share_id, sender, name, peer, enc, ciphertext, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (share_id) DO NOTHING",
    )
    .bind(&share.id)
    .bind(&share.from)
    .bind(&share.name)
    .bind(peer.to_string())
    .bind(&share.enc)
    .bind(&share.ciphertext)
    .bind(received_at)
    .execute(tx)
    .await?
    .rows_affected();
    Ok(inserted == 1)
}

/// Records a request for a share this node holds; asking again refreshes the pending request and
/// restarts its lifetime. Returns the request id, or `None` if the share isn't held.
async fn store_request(
    tx: &mut SqliteConnection,
    requester: PeerId,
    share_id: &str,
    reply_key: &[u8],
    requested_at: i64,
) -> anyhow::Result<Option<i64>> {
    Ok(sqlx::query_scalar::<_, i64>(
        "INSERT INTO share_requests (requester, share_id, reply_key, requested_at)
         SELECT ?, share_id, ?, ? FROM shares WHERE share_id = ?
         ON CONFLICT (requester, share_id) WHERE status = 'pending'
         DO UPDATE SET reply_key = excluded.reply_key, requested_at = excluded.requested_at
         RETURNING id",
    )
    .bind(requester.to_string())
    .bind(reply_key)
    .bind(requested_at)
    .bind(share_id)
    .fetch_optional(tx)
    .await?)
}

async fn handle_event(
    swarm: &mut Swarm<net::Behaviour>,
    state: &mut State,
    event: SwarmEvent<BehaviourEvent>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("listening on {address}/p2p/{}", swarm.local_peer_id());
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            info!(peer = %peer_id, addr = %endpoint.get_remote_address(), "connected");
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            info!(peer = %peer_id, ?cause, "disconnected");
        }
        SwarmEvent::IncomingConnectionError {
            peer_id,
            send_back_addr,
            error,
            ..
        } => {
            warn!(peer = ?peer_id, addr = %send_back_addr, "rejected incoming connection: {error}");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            warn!(peer = ?peer_id, "outgoing connection failed: {error}");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { peer, result, .. })) => {
            match result {
                Ok(rtt) => info!(%peer, ?rtt, "ping"),
                Err(e) => warn!(%peer, "ping failed: {e}"),
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Rpc(event)) => handle_rpc(swarm, state, event).await,
        _ => {}
    }
}

async fn handle_rpc(
    swarm: &mut Swarm<net::Behaviour>,
    state: &mut State,
    event: request_response::Event<Request, RpcReply>,
) {
    match event {
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        } => {
            let reply = handle_call(state, peer, request).await;
            if swarm
                .behaviour_mut()
                .rpc
                .send_response(channel, reply)
                .is_err()
            {
                warn!(%peer, "could not reply, connection closed");
            }
        }
        request_response::Event::Message {
            peer,
            message: request_response::Message::Response { request_id, .. },
            ..
        } => {
            warn!(%peer, %request_id, "unexpected response; nodes don't make calls");
        }
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            warn!(%peer, %request_id, "outbound call failed: {error}");
        }
        request_response::Event::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            warn!(%peer, %request_id, "inbound call failed: {error}");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

/// Answers a call. Only clients may call; other nodes can just ping. Share values are never
/// logged, and the node can't read them anyway.
async fn handle_call(state: &mut State, peer: PeerId, request: Request) -> RpcReply {
    let Request::Command { id, ts, cmd } = request else {
        return Err(RpcError::NotACommand);
    };
    if !state.clients.contains(&peer) {
        warn!(%peer, "call from a peer that isn't a client");
        return Err(RpcError::NotAClient);
    }

    match cmd {
        Command::NewShare(share) => {
            share.validate().map_err(invalid)?;
            let share_id = share.id.clone();
            let row_id = state
                .inbox
                .push(peer, id, ts, InboxCommand::NewShare(share))
                .await
                .map_err(internal)?;
            info!(%peer, id, row_id, %share_id, "new share queued");
            Ok(Response::Queued)
        }
        Command::RequestShare {
            share_id,
            reply_key,
        } => {
            crypto::share_public_key(&reply_key).map_err(invalid)?;
            let cmd = InboxCommand::RequestShare {
                share_id: share_id.clone(),
                reply_key,
            };
            let row_id = state
                .inbox
                .push(peer, id, ts, cmd)
                .await
                .map_err(internal)?;
            info!(%peer, id, row_id, %share_id, "share request queued");
            Ok(Response::Queued)
        }
        Command::ListShares { after, limit } => list_shares(&state.inbox.db, after, limit).await,
        Command::ListRequests { after, limit } => {
            list_requests(&state.inbox.db, after, limit).await
        }
        Command::Challenge { request } => challenge(state, peer, request).await,
        Command::Approve {
            request,
            proof,
            share,
        } => approve(state, peer, request, &proof, share).await,
        Command::FetchShare(share_id) => fetch_share(state, peer, &share_id).await,
    }
}

fn invalid(e: impl std::fmt::Display) -> RpcError {
    RpcError::Invalid(e.to_string())
}

fn internal(e: impl std::fmt::Display) -> RpcError {
    error!("call failed: {e:#}");
    RpcError::Internal
}

fn timestamp(secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default()
}

/// Pages are fetched with one extra row; if it's there, drops it and returns the cursor for the
/// next page.
fn next_cursor<T>(rows: &mut Vec<T>, limit: u32, id: impl Fn(&T) -> i64) -> Option<i64> {
    if rows.len() <= limit as usize {
        return None;
    }
    rows.truncate(limit as usize);
    rows.last().map(id)
}

#[derive(sqlx::FromRow)]
struct ShareRow {
    id: i64,
    share_id: String,
    name: String,
    sender: String,
    received_at: i64,
}

async fn list_shares(db: &SqlitePool, after: Option<i64>, limit: u32) -> RpcReply {
    let limit = limit.clamp(1, MAX_PAGE);
    let mut rows: Vec<ShareRow> = sqlx::query_as(
        "SELECT id, share_id, name, sender, received_at FROM shares
         WHERE id > ? ORDER BY id LIMIT ?",
    )
    .bind(after.unwrap_or(0))
    .bind(i64::from(limit) + 1)
    .fetch_all(db)
    .await
    .map_err(internal)?;

    let next = next_cursor(&mut rows, limit, |r| r.id);
    let shares = rows
        .into_iter()
        .map(|r| ShareInfo {
            row: r.id,
            share_id: r.share_id,
            name: r.name,
            from: r.sender,
            received_at: timestamp(r.received_at),
        })
        .collect();
    Ok(Response::Shares { shares, next })
}

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: i64,
    requester: String,
    share_id: String,
    requested_at: i64,
    status: String,
}

impl From<RequestRow> for AwaitingApproval {
    fn from(row: RequestRow) -> Self {
        Self {
            from: row.requester,
            id: row.id.to_string(),
            share_id: row.share_id,
            timestamp: timestamp(row.requested_at),
            status: row.status,
        }
    }
}

async fn list_requests(db: &SqlitePool, after: Option<i64>, limit: u32) -> RpcReply {
    let limit = limit.clamp(1, MAX_PAGE);
    let mut rows: Vec<RequestRow> = sqlx::query_as(
        "SELECT id, requester, share_id, requested_at, status FROM share_requests
         WHERE status = 'pending' AND requested_at > unixepoch() - ? AND id > ?
         ORDER BY id LIMIT ?",
    )
    .bind(REQUEST_TTL_SECS)
    .bind(after.unwrap_or(0))
    .bind(i64::from(limit) + 1)
    .fetch_all(db)
    .await
    .map_err(internal)?;

    let next = next_cursor(&mut rows, limit, |r| r.id);
    let requests = rows.into_iter().map(AwaitingApproval::from).collect();
    Ok(Response::Requests { requests, next })
}

#[derive(sqlx::FromRow)]
struct ChallengeRow {
    id: i64,
    requester: String,
    share_id: String,
    requested_at: i64,
    status: String,
    /// Seconds until the request expires; zero or less once it has.
    remaining: i64,
    reply_key: Vec<u8>,
    sender: String,
    name: String,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// First half of an approval: hands the approver the stored share and a challenge that only the
/// holder of this node's share secret key can answer.
async fn challenge(state: &mut State, approver: PeerId, request: i64) -> RpcReply {
    let row: Option<ChallengeRow> = sqlx::query_as(
        "SELECT r.id, r.requester, r.share_id, r.requested_at, r.status,
                r.requested_at + ? - unixepoch() AS remaining, r.reply_key,
                s.sender, s.name, s.enc, s.ciphertext
         FROM share_requests r JOIN shares s ON s.share_id = r.share_id
         WHERE r.id = ?",
    )
    .bind(REQUEST_TTL_SECS)
    .bind(request)
    .fetch_optional(&state.inbox.db)
    .await
    .map_err(internal)?;
    let Some(row) = row else {
        return Err(RpcError::NotFound);
    };
    if row.status != "pending" {
        return Err(RpcError::Invalid(format!(
            "request {request} is {}",
            row.status
        )));
    }
    let Ok(remaining @ 1..) = u64::try_from(row.remaining) else {
        return Err(RpcError::Invalid(format!("request {request} has expired")));
    };

    let context = crypto::approval_context(
        &state.local.to_string(),
        &approver.to_string(),
        &row.requester,
        request,
        &row.share_id,
    );
    let (enc, expected) =
        crypto::approval_challenge(&state.share_key, &context).map_err(internal)?;
    let now = Instant::now();
    state.challenges.retain(|_, c| c.expires > now);
    state.challenges.insert(
        (request, approver),
        Challenge {
            expected,
            expires: now + CHALLENGE_TTL.min(Duration::from_secs(remaining)),
        },
    );
    info!(%approver, request, "approval challenge issued");

    let share = SealedShare {
        from: row.sender,
        id: row.share_id.clone(),
        name: row.name,
        enc: row.enc,
        ciphertext: row.ciphertext,
    };
    let request = AwaitingApproval::from(RequestRow {
        id: row.id,
        requester: row.requester,
        share_id: row.share_id,
        requested_at: row.requested_at,
        status: row.status,
    });
    Ok(Response::Challenge {
        enc,
        request,
        reply_key: row.reply_key,
        share,
    })
}

/// Second half of an approval: checks the proof and stores the share the approver re-sealed for
/// the requester.
async fn approve(
    state: &mut State,
    approver: PeerId,
    request: i64,
    proof: &[u8],
    share: SealedShare,
) -> RpcReply {
    // A challenge is used once, whether the proof is right or not.
    let challenge = state
        .challenges
        .remove(&(request, approver))
        .filter(|c| c.expires > Instant::now());
    if !challenge.is_some_and(|c| crypto::proof_matches(&c.expected, proof)) {
        warn!(%approver, request, "approval rejected: wrong or expired proof");
        return Err(RpcError::BadProof);
    }
    share.validate().map_err(invalid)?;

    let approved = sqlx::query(
        "UPDATE share_requests
         SET status = 'approved', approved_by = ?, approved_at = unixepoch(),
             delivery_enc = ?, delivery_ciphertext = ?
         WHERE id = ? AND status = 'pending' AND share_id = ?
           AND requested_at > unixepoch() - ?",
    )
    .bind(approver.to_string())
    .bind(&share.enc)
    .bind(&share.ciphertext)
    .bind(request)
    .bind(&share.id)
    .bind(REQUEST_TTL_SECS)
    .execute(&state.inbox.db)
    .await
    .map_err(internal)?
    .rows_affected();
    if approved == 0 {
        return Err(RpcError::Invalid(format!(
            "request {request} for share {} is no longer pending, or has expired",
            share.id
        )));
    }
    info!(%approver, request, share_id = %share.id, "share request approved");
    Ok(Response::Approved)
}

#[derive(sqlx::FromRow)]
struct FetchRow {
    id: i64,
    requested_at: i64,
    /// Approved, and still in its fetch window.
    fresh: bool,
    /// Pending, and not expired.
    live: bool,
    sender: String,
    name: String,
    delivery_enc: Option<Vec<u8>>,
    delivery_ciphertext: Option<Vec<u8>>,
}

/// The requester's view of its request for a share, with the re-sealed share while the approval
/// is fresh.
async fn fetch_share(state: &State, requester: PeerId, share_id: &str) -> RpcReply {
    // Prefer an approval still in its fetch window over a newer pending request.
    let row: Option<FetchRow> = sqlx::query_as(
        "SELECT r.id, r.requested_at,
                r.status = 'approved' AND r.approved_at > unixepoch() - ? AS fresh,
                r.status = 'pending' AND r.requested_at > unixepoch() - ? AS live,
                s.sender, s.name, r.delivery_enc, r.delivery_ciphertext
         FROM share_requests r JOIN shares s ON s.share_id = r.share_id
         WHERE r.requester = ? AND r.share_id = ?
         ORDER BY fresh DESC, r.id DESC LIMIT 1",
    )
    .bind(APPROVAL_TTL_SECS)
    .bind(REQUEST_TTL_SECS)
    .bind(requester.to_string())
    .bind(share_id)
    .fetch_optional(&state.inbox.db)
    .await
    .map_err(internal)?;
    let Some(row) = row else {
        return Err(RpcError::NotFound);
    };

    let (status, share) = match (row.fresh, row.delivery_enc, row.delivery_ciphertext) {
        (true, Some(enc), Some(ciphertext)) => {
            let share = SealedShare {
                from: row.sender,
                id: share_id.into(),
                name: row.name,
                enc,
                ciphertext,
            };
            ("approved", Some(share))
        }
        _ if row.live => ("pending", None),
        _ => ("expired", None),
    };
    Ok(Response::Share {
        status: AwaitingResponse {
            to: state.local.to_string(),
            id: row.id.to_string(),
            share_id: share_id.into(),
            timestamp: timestamp(row.requested_at),
            status: status.into(),
        },
        share,
    })
}

#[cfg(test)]
mod tests {
    use hpke::Kem as _;

    use super::*;
    use crate::crypto::{STORAGE_INFO, ShareKem, ShareSecretKey};

    struct Fixture {
        state: State,
        secret_key: ShareSecretKey,
        approver: PeerId,
    }

    async fn fixture() -> Fixture {
        // One connection that never closes, or the in-memory database would not be shared.
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let (secret_key, share_key) = ShareKem::gen_keypair();
        let approver = PeerId::random();
        let share = SealedShare::seal(
            "dealer",
            "s1",
            "test",
            b"payload",
            &share_key,
            STORAGE_INFO,
            &[],
        )
        .unwrap();
        store_share(
            &mut db.acquire().await.unwrap(),
            PeerId::random(),
            0,
            &share,
        )
        .await
        .unwrap();
        let state = State {
            inbox: Inbox {
                db,
                worker: mpsc::unbounded_channel().0,
            },
            share_key,
            local: PeerId::random(),
            clients: HashSet::from([approver]),
            challenges: HashMap::new(),
        };
        Fixture {
            state,
            secret_key,
            approver,
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// A pending request for share `s1`, made `age` seconds ago.
    async fn request(f: &Fixture, requester: PeerId, age: i64) -> i64 {
        let mut conn = f.state.inbox.db.acquire().await.unwrap();
        store_request(&mut conn, requester, "s1", b"reply key", now() - age)
            .await
            .unwrap()
            .unwrap()
    }

    /// Moves a request's `column` timestamp `secs` into the past.
    async fn backdate(f: &Fixture, request: i64, column: &str, secs: i64) {
        let sql = match column {
            "requested_at" => {
                "UPDATE share_requests SET requested_at = requested_at - ? WHERE id = ?"
            }
            "approved_at" => "UPDATE share_requests SET approved_at = approved_at - ? WHERE id = ?",
            _ => unreachable!("unknown column {column}"),
        };
        sqlx::query(sql)
            .bind(secs)
            .bind(request)
            .execute(&f.state.inbox.db)
            .await
            .unwrap();
    }

    async fn approve_request(f: &mut Fixture, request: i64) -> RpcReply {
        let Response::Challenge {
            enc,
            request: details,
            share,
            ..
        } = challenge(&mut f.state, f.approver, request).await?
        else {
            panic!("expected a challenge");
        };
        let context = crypto::approval_context(
            &f.state.local.to_string(),
            &f.approver.to_string(),
            &details.from,
            request,
            &details.share_id,
        );
        let proof = crypto::approval_proof(&f.secret_key, &enc, &context).unwrap();
        // The stored share stands in for the re-sealed one; the node only checks its format.
        approve(&mut f.state, f.approver, request, &proof, share).await
    }

    /// The requester's status for `s1`, and whether the share came with it.
    async fn fetch(f: &Fixture, requester: PeerId) -> Result<(String, bool), RpcError> {
        let Response::Share { status, share } = fetch_share(&f.state, requester, "s1").await?
        else {
            panic!("expected a share reply");
        };
        Ok((status.status, share.is_some()))
    }

    async fn listed(f: &Fixture) -> Vec<String> {
        let Ok(Response::Requests { requests, .. }) =
            list_requests(&f.state.inbox.db, None, 10).await
        else {
            panic!("expected requests");
        };
        requests.into_iter().map(|r| r.id).collect()
    }

    #[tokio::test]
    async fn expired_requests_are_refused_and_deleted() {
        let mut f = fixture().await;
        let (fresh_requester, old_requester) = (PeerId::random(), PeerId::random());
        let fresh = request(&f, fresh_requester, 0).await;
        let old = request(&f, old_requester, REQUEST_TTL_SECS).await;

        assert_eq!(listed(&f).await, [fresh.to_string()]);
        let Err(RpcError::Invalid(reason)) = challenge(&mut f.state, f.approver, old).await else {
            panic!("an expired request must not get a challenge");
        };
        assert!(reason.contains("expired"), "{reason}");
        assert_eq!(
            fetch(&f, old_requester).await.unwrap(),
            ("expired".into(), false)
        );
        assert_eq!(
            fetch(&f, fresh_requester).await.unwrap(),
            ("pending".into(), false)
        );

        assert_eq!(delete_expired_requests(&f.state.inbox.db).await.unwrap(), 1);
        assert!(matches!(
            fetch(&f, old_requester).await,
            Err(RpcError::NotFound)
        ));
        assert_eq!(listed(&f).await, [fresh.to_string()]);
    }

    #[tokio::test]
    async fn approval_fails_once_the_request_expires() {
        let mut f = fixture().await;
        let request = request(&f, PeerId::random(), 0).await;
        let Response::Challenge {
            enc,
            request: details,
            share,
            ..
        } = challenge(&mut f.state, f.approver, request).await.unwrap()
        else {
            panic!("expected a challenge");
        };
        // The request expires while the approver is answering.
        backdate(&f, request, "requested_at", REQUEST_TTL_SECS).await;

        let context = crypto::approval_context(
            &f.state.local.to_string(),
            &f.approver.to_string(),
            &details.from,
            request,
            &details.share_id,
        );
        let proof = crypto::approval_proof(&f.secret_key, &enc, &context).unwrap();
        let result = approve(&mut f.state, f.approver, request, &proof, share).await;
        assert!(matches!(result, Err(RpcError::Invalid(_))), "{result:?}");
    }

    #[tokio::test]
    async fn challenge_never_outlives_its_request() {
        let mut f = fixture().await;
        let request = request(&f, PeerId::random(), REQUEST_TTL_SECS - 10).await;
        challenge(&mut f.state, f.approver, request).await.unwrap();
        let challenge = &f.state.challenges[&(request, f.approver)];
        assert!(challenge.expires <= Instant::now() + Duration::from_secs(10));
    }

    #[tokio::test]
    async fn approved_requests_are_deleted_after_the_fetch_window() {
        let mut f = fixture().await;
        let requester = PeerId::random();
        let request = request(&f, requester, 0).await;
        approve_request(&mut f, request).await.unwrap();
        assert_eq!(
            fetch(&f, requester).await.unwrap(),
            ("approved".into(), true)
        );
        assert_eq!(delete_expired_requests(&f.state.inbox.db).await.unwrap(), 0);

        backdate(&f, request, "approved_at", APPROVAL_TTL_SECS).await;
        assert_eq!(
            fetch(&f, requester).await.unwrap(),
            ("expired".into(), false)
        );
        assert_eq!(delete_expired_requests(&f.state.inbox.db).await.unwrap(), 1);
        assert!(matches!(
            fetch(&f, requester).await,
            Err(RpcError::NotFound)
        ));
    }

    #[tokio::test]
    async fn queued_requests_keep_their_receive_time() {
        let f = fixture().await;
        let db = &f.state.inbox.db;
        let (old_requester, fresh_requester) = (PeerId::random(), PeerId::random());
        for (requester, age) in [(old_requester, REQUEST_TTL_SECS), (fresh_requester, 10)] {
            let entry = InboxEntry {
                id: 1,
                ts: 0,
                cmd: InboxCommand::RequestShare {
                    share_id: "s1".into(),
                    reply_key: b"reply key".to_vec(),
                },
            };
            let row_id =
                sqlx::query("INSERT INTO inbox (peer, payload, received_at) VALUES (?, ?, ?)")
                    .bind(requester.to_string())
                    .bind(serde_json::to_string(&entry).unwrap())
                    .bind(now() - age)
                    .execute(db)
                    .await
                    .unwrap()
                    .last_insert_rowid();
            process_inbox_row(db, row_id).await.unwrap();
        }

        let stored: Vec<(String, i64)> =
            sqlx::query_as("SELECT requester, unixepoch() - requested_at FROM share_requests")
                .fetch_all(db)
                .await
                .unwrap();
        assert_eq!(stored.len(), 1, "the expired request must not be stored");
        assert_eq!(stored[0].0, fresh_requester.to_string());
        assert!((10..=11).contains(&stored[0].1), "age {}", stored[0].1);
        let inbox: i64 = sqlx::query_scalar("SELECT count(*) FROM inbox")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(inbox, 0);
    }

    #[tokio::test]
    async fn inbox_worker_stops_on_shutdown() {
        let f = fixture().await;
        // The sender stays alive, so only the token can stop the worker.
        let (_queue, queued) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let worker = tokio::spawn(inbox_worker(
            f.state.inbox.db.clone(),
            queued,
            shutdown.clone(),
        ));
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("worker did not stop")
            .unwrap();
    }
}
