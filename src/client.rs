//! The client: splits secrets into one sealed share per node, requests shares back, approves
//! requests on its own node and restores secrets.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, IsTerminal as _, Read as _, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, bail, ensure};
use futures::StreamExt as _;
use hpke::Serializable as _;
use libp2p::{
    Multiaddr, PeerId, Swarm, identity::Keypair, multiaddr::Protocol, request_response,
    swarm::SwarmEvent,
};
use num_bigint::{BigRng010 as _, BigUint};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    Command, P_HEX, Request, Response,
    crypto::{self, DELIVERY_INFO, STORAGE_INFO, SealedShare, SharePayload, SharePublicKey},
    evaluate_horner, keys,
    net::{self, BehaviourEvent},
    now, threshold_restore,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Prepended to a secret before splitting so leading zero bytes survive the number round trip.
const SECRET_PREFIX: u8 = 0x01;

#[derive(Debug, clap::Args)]
pub struct ClientArgs {
    /// Client config file
    #[arg(long, default_value = "client.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: ClientCommand,
}

#[derive(Debug, clap::Subcommand)]
enum ClientCommand {
    /// Split a secret read from stdin into one share per node and push them
    Push {
        /// Id the secret is stored and requested under
        #[arg(long)]
        id: String,
        /// Human readable name, stored next to the id
        #[arg(long)]
        name: String,
        /// Number of shares needed to restore the secret
        #[arg(long)]
        threshold: u32,
    },
    /// Ask every node for its share of a secret; unreachable nodes are skipped
    Request {
        #[arg(long)]
        id: String,
    },
    /// List the shares a node holds
    List {
        /// Node name from the config
        #[arg(long)]
        node: String,
        /// Start after this row (from the previous page)
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// List requests waiting for approval, on this client's own node unless --node is given
    Requests {
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Approve a request on this client's own node and send its share to the requester
    Approve {
        #[arg(long)]
        request: i64,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Fetch the approved shares of a secret from every reachable node and restore it
    Restore {
        #[arg(long)]
        id: String,
        /// Write the secret to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

pub async fn run(args: ClientArgs) -> anyhow::Result<()> {
    let mut client = Client::load(&args.config)?;
    match args.command {
        ClientCommand::Push {
            id,
            name,
            threshold,
        } => client.push(&id, &name, threshold).await,
        ClientCommand::Request { id } => client.request(&id).await,
        ClientCommand::List { node, after, limit } => {
            let node = client.node(&node)?;
            client.list(node, after, limit).await
        }
        ClientCommand::Requests { node, after, limit } => {
            let node = match node {
                Some(name) => client.node(&name)?,
                None => client.own_node()?,
            };
            client.requests(node, after, limit).await
        }
        ClientCommand::Approve { request, yes } => client.approve(request, yes).await,
        ClientCommand::Restore { id, out } => client.restore(&id, out.as_deref()).await,
    }
}

/// `client.toml`. Relative paths are resolved against the directory of the config file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// TLS identity, from `asphalt keygen`.
    key: PathBuf,
    /// This client's share keypair: the one its own node stores shares under. Shares other
    /// nodes release to this client are re-sealed to `share_pub`.
    share_key: PathBuf,
    share_pub: PathBuf,
    nodes: Vec<NodeFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeFile {
    name: String,
    /// `/ip4/<ip>/udp/<port>/quic-v1/p2p/<peer-id>`
    addr: String,
    share_pub: PathBuf,
}

struct Node {
    name: String,
    peer: PeerId,
    addr: Multiaddr,
    share_pub: SharePublicKey,
    /// Stores shares under this client's share key, so only this client can approve there.
    own: bool,
}

struct Client {
    swarm: Swarm<net::Behaviour>,
    identity: Keypair,
    local: PeerId,
    share_key: PathBuf,
    share_pub: SharePublicKey,
    nodes: Vec<Node>,
}

impl Client {
    fn load(config: &Path) -> anyhow::Result<Self> {
        let text = fs::read_to_string(config)
            .with_context(|| format!("failed to read {}", config.display()))?;
        let file: ConfigFile =
            toml::from_str(&text).with_context(|| format!("invalid {}", config.display()))?;
        let dir = config.parent().unwrap_or(Path::new("."));

        let identity = keys::load_keypair(&dir.join(&file.key))?;
        let share_pub = keys::load_share_public_key(&dir.join(&file.share_pub))?;
        let nodes = file
            .nodes
            .into_iter()
            .map(|node| {
                let addr: Multiaddr = node
                    .addr
                    .parse()
                    .with_context(|| format!("node {}: invalid address", node.name))?;
                let Some(Protocol::P2p(peer)) = addr.iter().last() else {
                    bail!("node {}: address must end with /p2p/<peer-id>", node.name);
                };
                let node_pub = keys::load_share_public_key(&dir.join(&node.share_pub))?;
                Ok(Node {
                    own: node_pub.to_bytes() == share_pub.to_bytes(),
                    name: node.name,
                    peer,
                    addr,
                    share_pub: node_pub,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(!nodes.is_empty(), "no nodes in {}", config.display());

        let swarm = net::swarm(identity.clone(), nodes.iter().map(|n| n.peer), CALL_TIMEOUT)?;
        Ok(Self {
            swarm,
            local: identity.public().to_peer_id(),
            identity,
            share_key: dir.join(file.share_key),
            share_pub,
            nodes,
        })
    }

    fn node(&self, name: &str) -> anyhow::Result<usize> {
        self.nodes
            .iter()
            .position(|n| n.name == name)
            .with_context(|| format!("no node named {name} in the config"))
    }

    fn own_node(&self) -> anyhow::Result<usize> {
        self.nodes
            .iter()
            .position(|n| n.own)
            .context("no node in the config stores shares under this client's share_pub")
    }

    /// Sends one call per `(node, command)` and waits for all replies. Each slot holds that
    /// node's reply, its refusal or the connection error.
    async fn call_all(&mut self, calls: Vec<(usize, Command)>) -> Vec<anyhow::Result<Response>> {
        // None in a case if a response for the request timed out
        let mut results: Vec<Option<anyhow::Result<Response>>> =
            calls.iter().map(|_| None).collect();
        let mut pending = HashMap::new();
        for (request_slot, (node, cmd)) in calls.into_iter().enumerate() {
            let node = &self.nodes[node];
            let request = Request::Command {
                id: rand::random(),
                ts: now(),
                cmd,
            };
            let request_id = self.swarm.behaviour_mut().rpc.send_request_with_addresses(
                &node.peer,
                request,
                vec![node.addr.clone()],
            );
            pending.insert(request_id, request_slot);
        }

        let mut dial_errors = HashMap::new();
        let timeout = tokio::time::sleep(CALL_TIMEOUT);
        tokio::pin!(timeout);
        while !pending.is_empty() {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    let (request_id, result) = match event {
                        SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), error, .. } => {
                            dial_errors.insert(peer, error.to_string());
                            continue;
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::Message {
                            message: request_response::Message::Response { request_id, response },
                            ..
                        })) => (request_id, response.map_err(|e| anyhow::anyhow!("refused: {e}"))),
                        SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::OutboundFailure {
                            peer, request_id, error, ..
                        })) => {
                            let error = match (&error, dial_errors.get(&peer)) {
                                (_, Some(dial)) => anyhow::anyhow!("{error}: {dial}"),
                                (
                                    request_response::OutboundFailure::Io(_)
                                    | request_response::OutboundFailure::ConnectionClosed,
                                    None,
                                ) => anyhow::anyhow!(
                                    "{error} (the node closed the connection; is this client's \
                                     peer id in its --allowclients?)"
                                ),
                                _ => anyhow::anyhow!("{error}"),
                            };
                            (request_id, Err(error))
                        }
                        _ => continue,
                    };
                    if let Some(slot) = pending.remove(&request_id) {
                        results[slot] = Some(result);
                    }
                }
                _ = &mut timeout => break,
            }
        }
        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(anyhow::anyhow!("no reply within {CALL_TIMEOUT:?}"))))
            .collect()
    }

    async fn call(&mut self, node: usize, cmd: Command) -> anyhow::Result<Response> {
        let name = self.nodes[node].name.clone();
        let mut results = self.call_all(vec![(node, cmd)]).await;
        results.pop().expect("one call").with_context(|| name)
    }

    /// Splits the secret with one share per node (x = 1..n in config order), signs each share
    /// and seals it to that node's share key, so no node ever sees a share in plaintext.
    async fn push(&mut self, id: &str, name: &str, threshold: u32) -> anyhow::Result<()> {
        let n = self.nodes.len();
        ensure!(
            threshold >= 2 && threshold as usize <= n,
            "threshold must be between 2 and the number of nodes ({n})"
        );
        let secret = read_secret()?;
        ensure!(!secret.is_empty(), "the secret is empty");
        ensure!(secret.len() <= 254, "the secret must be at most 254 bytes");
        let mut encoded = Zeroizing::new(Vec::with_capacity(1 + secret.len()));
        encoded.push(SECRET_PREFIX);
        encoded.extend_from_slice(&secret);

        let p = prime();
        let mut poly = vec![BigUint::ZERO; threshold as usize];
        unsafe { *poly.get_unchecked_mut(0) = BigUint::from_bytes_be(&encoded) };
        let mut rng = rand::rng();
        (1..threshold as usize).for_each(|i| unsafe {
            *poly.get_unchecked_mut(i) = rng.random_biguint_range(&BigUint::ZERO, &p)
        });
        let split: [u8; 16] = rand::random();
        let from = self.local.to_string();

        let mut calls = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
            let x = i as u32 + 1;
            let y = fixed_width(&evaluate_horner(&poly, &BigUint::from(x), &p), &p);
            let payload = SharePayload::signed(&self.identity, id, name, x, threshold, &split, y)?;
            let sealed = SealedShare::seal(
                &from,
                id,
                name,
                &payload.to_bytes()?,
                &node.share_pub,
                STORAGE_INFO,
                &[],
            )?;
            calls.push((i, Command::NewShare(sealed)));
        }

        let results = self.call_all(calls).await;
        let mut queued = 0;
        for (node, result) in self.nodes.iter().zip(results) {
            match result {
                Ok(_) => {
                    queued += 1;
                    eprintln!("{}: share stored", node.name);
                }
                Err(e) => eprintln!("{}: {e:#}", node.name),
            }
        }
        ensure!(
            queued >= threshold,
            "only {queued} of {n} nodes took a share; restoring needs {threshold}"
        );
        eprintln!("pushed {id}: {threshold} of {n} shares restore it");
        Ok(())
    }

    /// Asks every node for its share of `id`, skipping nodes that can't be reached; approved
    /// shares get re-sealed to this client's share key.
    async fn request(&mut self, id: &str) -> anyhow::Result<()> {
        let reply_key = self.share_pub.to_bytes().to_vec();
        let calls = (0..self.nodes.len())
            .map(|i| {
                let cmd = Command::RequestShare {
                    share_id: id.into(),
                    reply_key: reply_key.clone(),
                };
                (i, cmd)
            })
            .collect();

        let results = self.call_all(calls).await;
        let mut requested = 0;
        for (node, result) in self.nodes.iter().zip(results) {
            match result {
                Ok(_) => {
                    requested += 1;
                    eprintln!("{}: requested", node.name);
                }
                Err(e) => eprintln!("{}: skipped: {e:#}", node.name),
            }
        }
        ensure!(requested > 0, "no node took the request");
        eprintln!(
            "each node's client now approves, you included on your own node \
             (`requests`, then `approve --request <id>`); then run `restore --id {id}`"
        );
        Ok(())
    }

    async fn list(&mut self, node: usize, after: Option<i64>, limit: u32) -> anyhow::Result<()> {
        let Response::Shares { shares, next } = self
            .call(node, Command::ListShares { after, limit })
            .await?
        else {
            bail!("unexpected reply");
        };
        if shares.is_empty() {
            eprintln!("no shares");
        }
        for share in shares {
            println!(
                "{}\t{}\t{}\tdealer {}\treceived {}",
                share.row,
                share.share_id,
                share.name,
                share.from,
                share.received_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }
        if let Some(next) = next {
            eprintln!("more: --after {next}");
        }
        Ok(())
    }

    async fn requests(
        &mut self,
        node: usize,
        after: Option<i64>,
        limit: u32,
    ) -> anyhow::Result<()> {
        let Response::Requests { requests, next } = self
            .call(node, Command::ListRequests { after, limit })
            .await?
        else {
            bail!("unexpected reply");
        };
        if requests.is_empty() {
            eprintln!("no pending requests");
        }
        for request in requests {
            println!(
                "{}\t{}\trequested by {}\tat {}",
                request.id,
                request.share_id,
                request.from,
                request.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }
        if let Some(next) = next {
            eprintln!("more: --after {next}");
        }
        Ok(())
    }

    /// Proves to its own node that this client holds the node's share key, and re-seals the
    /// stored share to the requester's key.
    async fn approve(&mut self, request: i64, yes: bool) -> anyhow::Result<()> {
        let node = self.own_node()?;
        let secret_key = keys::load_share_secret_key(&self.share_key)?;
        ensure!(
            crypto::public_key_of(&secret_key).to_bytes() == self.share_pub.to_bytes(),
            "{} is not the secret key for share_pub",
            self.share_key.display()
        );

        let Response::Challenge {
            enc,
            request: details,
            reply_key,
            share,
        } = self.call(node, Command::Challenge { request }).await?
        else {
            bail!("unexpected reply");
        };
        let payload = share.open(&secret_key, STORAGE_INFO, &[])?;
        SharePayload::from_bytes(&payload)?.verify(&share.from, &share.id, &share.name)?;

        eprintln!("request {request} on {}:", self.nodes[node].name);
        eprintln!("  share      {} ({})", share.id, share.name);
        eprintln!("  dealer     {}", share.from);
        eprintln!("  requester  {}", details.from);
        eprintln!(
            "  requested  {}",
            details.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );
        if !yes {
            confirm("send this share to the requester? [y/N] ")?;
        }

        let node_peer = self.nodes[node].peer.to_string();
        let delivered = SealedShare::seal(
            &share.from,
            &share.id,
            &share.name,
            &payload,
            &crypto::share_public_key(&reply_key)?,
            DELIVERY_INFO,
            &crypto::delivery_context(&node_peer, &details.from, request),
        )?;
        let context = crypto::approval_context(
            &node_peer,
            &self.local.to_string(),
            &details.from,
            request,
            &details.share_id,
        );
        let proof = crypto::approval_proof(&secret_key, &enc, &context)?.to_vec();

        let cmd = Command::Approve {
            request,
            proof,
            share: delivered,
        };
        let Response::Approved = self.call(node, cmd).await? else {
            bail!("unexpected reply");
        };
        eprintln!("approved request {request}");
        Ok(())
    }

    /// Fetches the shares released to this client from every node it can reach, checks the
    /// dealer signatures, and once it has at least `threshold` shares of one split, combines all
    /// of them into the secret.
    async fn restore(&mut self, id: &str, out: Option<&Path>) -> anyhow::Result<()> {
        if let Some(out) = out {
            ensure!(!out.exists(), "{} already exists", out.display());
        }
        let secret_key = keys::load_share_secret_key(&self.share_key)?;
        let local = self.local.to_string();
        let calls = (0..self.nodes.len())
            .map(|i| (i, Command::FetchShare(id.into())))
            .collect();
        let results = self.call_all(calls).await;

        let mut received = Vec::new();
        for (node, result) in self.nodes.iter().zip(results) {
            let response = match result {
                Ok(response) => response,
                Err(e) => {
                    eprintln!("{}: skipped: {e:#}", node.name);
                    continue;
                }
            };
            let Response::Share { status, share } = response else {
                eprintln!("{}: unexpected reply", node.name);
                continue;
            };
            let Some(share) = share else {
                eprintln!("{}: request {} is {}", node.name, status.id, status.status);
                continue;
            };
            let opened = (|| {
                ensure!(
                    share.id == id,
                    "node sent share {} instead of {id}",
                    share.id
                );
                let request: i64 = status.id.parse()?;
                let delivery = crypto::delivery_context(&node.peer.to_string(), &local, request);
                let bytes = share.open(&secret_key, DELIVERY_INFO, &delivery)?;
                let payload = SharePayload::from_bytes(&bytes)?;
                payload.verify(&share.from, &share.id, &share.name)?;
                Ok(payload)
            })();
            match opened {
                Ok(payload) => {
                    eprintln!("{}: got share x={}", node.name, payload.x);
                    received.push((share.from, payload));
                }
                Err(e) => eprintln!("{}: rejected share: {e:#}", node.name),
            }
        }

        // Only shares of the same split by the same dealer combine; use the largest such group.
        let mut groups: HashMap<(&str, &[u8], u32), BTreeMap<u32, &SharePayload>> = HashMap::new();
        for (from, payload) in &received {
            groups
                .entry((from, &payload.split, payload.threshold))
                .or_default()
                .insert(payload.x, payload);
        }
        let Some(((dealer, _, threshold), shares)) =
            groups.into_iter().max_by_key(|(_, shares)| shares.len())
        else {
            bail!("no shares of {id} received yet");
        };
        ensure!(
            shares.len() >= threshold as usize,
            "have {} of the {threshold} shares {id} needs; wait for more approvals",
            shares.len()
        );

        // Any `threshold` points determine the polynomial, and extra points lie on it too, so
        // interpolating through all of them gives the same secret.
        let p = prime();
        let (xs, ys): (Vec<_>, Vec<_>) = shares
            .values()
            .map(|s| (BigUint::from(s.x), BigUint::from_bytes_be(&s.y)))
            .unzip();
        let encoded = Zeroizing::new(threshold_restore(&xs, &ys, &p).to_bytes_be());
        let Some((&SECRET_PREFIX, secret)) = encoded.split_first() else {
            bail!("the shares don't combine into a valid secret");
        };

        match out {
            Some(path) => keys::create_key_file(path, false)?.write_all(secret)?,
            None => io::stdout().write_all(secret)?,
        }
        eprintln!(
            "restored {id} from {} shares ({threshold} needed), dealt by {dealer}",
            xs.len()
        );
        Ok(())
    }
}

fn prime() -> BigUint {
    BigUint::parse_bytes(P_HEX.as_bytes(), 16).expect("P_HEX is valid hex")
}

/// `value` big-endian, left-padded to the prime's width so share length says nothing about it.
fn fixed_width(value: &BigUint, p: &BigUint) -> Vec<u8> {
    let width = (p.bits() as usize).div_ceil(8);
    let bytes = value.to_bytes_be();
    let mut out = vec![0; width - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

/// The secret to split: typed without echo on a terminal, otherwise all of stdin as is.
fn read_secret() -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if io::stdin().is_terminal() {
        Ok(Zeroizing::new(
            rpassword::prompt_password("secret: ")?.into_bytes(),
        ))
    } else {
        let mut secret = Zeroizing::new(Vec::new());
        io::stdin().read_to_end(&mut secret)?;
        Ok(secret)
    }
}

fn confirm(prompt: &str) -> anyhow::Result<()> {
    ensure!(
        io::stdin().is_terminal(),
        "stdin is not a terminal; pass --yes to approve without confirming"
    );
    eprint!("{prompt}");
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    ensure!(matches!(answer.trim(), "y" | "yes"), "not approved");
    Ok(())
}
