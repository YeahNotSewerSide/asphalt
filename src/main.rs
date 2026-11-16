use std::{
    ops::Mul as _,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::Utc;
use libp2p::StreamProtocol;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

mod client;
mod crypto;
mod keys;
mod net;
mod node;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, PeerId};
use tracing_subscriber::EnvFilter;

use crate::crypto::SealedShare;

// rfc5114: 2048 bit prime
const P_HEX: &str = concat!(
    "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30",
    "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD",
    "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B",
    "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C",
    "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E",
    "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9",
    "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026",
    "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3",
    "75F26375D7014103A4B54330C198AF126116D2276E11715F",
    "693877FAD7EF09CADB094AE91E1A1597",
);

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/asphalt/1.0.0");

/// Evaluates the polynomial at `x` modulo `prime`. Without the reduction a share at `x` would
/// reveal `secret mod x`.
pub fn evaluate_horner(poly: &[BigUint], x: &BigUint, prime: &BigUint) -> BigUint {
    let mut y = poly.last().unwrap().clone();
    for c in poly.iter().rev().skip(1) {
        y = y.mul(x);
        y = (c + y) % prime;
    }
    y
}

fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let a_mod = a % p;
    let b_mod = b % p;

    if a_mod >= b_mod {
        (a_mod - b_mod) % p
    } else {
        (p - (b_mod - a_mod)) % p
    }
}

pub fn lagrange(xs: &[BigUint], i: usize, p: &BigUint) -> BigUint {
    let xi = xs[i].clone();
    let mut lagrange_up = BigUint::ONE;
    let mut lagrange_down = BigUint::ONE;
    for xj in xs
        .iter()
        .enumerate()
        .filter_map(|(j, xj)| if j == i { None } else { Some(xj) })
    {
        lagrange_up = lagrange_up * mod_sub(&BigUint::ZERO, xj, p);
        lagrange_down = lagrange_down * mod_sub(&xi, xj, p);
    }

    lagrange_down = lagrange_down.modinv(p).unwrap();

    (lagrange_up * lagrange_down) % p
}

pub fn threshold_restore(xs: &[BigUint], ys: &[BigUint], p: &BigUint) -> BigUint {
    if xs.len() != ys.len() {
        panic!();
    }
    let mut restored_secret = BigUint::ZERO;
    for i in 0..xs.len() {
        let lagrange = lagrange(xs, i, p);
        restored_secret = restored_secret + (ys.get(i).unwrap().mul(&lagrange));
    }
    restored_secret % p
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub from: String,
    pub id: String,
    pub name: String,
    pub share: BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingApproval {
    pub from: String,
    pub id: String,
    pub share_id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingResponse {
    pub to: String,
    pub id: String,
    pub share_id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub status: String,
}

/// Calls a client makes on a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// A share the dealer sealed to the receiving node's share key.
    NewShare(SealedShare),
    /// Ask for a share. Once the client holding the node's share key approves, the share is
    /// re-sealed to `reply_key`.
    RequestShare {
        share_id: String,
        #[serde(with = "hex")]
        reply_key: Vec<u8>,
    },
    /// The shares the node holds, at most `limit` after row `after`.
    ListShares { after: Option<i64>, limit: u32 },
    /// Requests waiting for approval, paged like `ListShares`.
    ListRequests { after: Option<i64>, limit: u32 },
    /// Starts approving a request: the node answers with a challenge for its share key.
    Challenge { request: i64 },
    /// Finishes approving: the challenge proof and the share re-sealed to the requester.
    Approve {
        request: i64,
        #[serde(with = "hex")]
        proof: Vec<u8>,
        share: SealedShare,
    },
    /// The caller's request for a share, with the share once approved.
    FetchShare(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Stored in the inbox and processed in the background.
    Queued,
    Shares {
        shares: Vec<ShareInfo>,
        next: Option<i64>,
    },
    Requests {
        requests: Vec<AwaitingApproval>,
        next: Option<i64>,
    },
    Challenge {
        #[serde(with = "hex")]
        enc: Vec<u8>,
        request: AwaitingApproval,
        #[serde(with = "hex")]
        reply_key: Vec<u8>,
        /// The stored share, for the approver to open and re-seal.
        share: SealedShare,
    },
    Approved,
    Share {
        status: AwaitingResponse,
        share: Option<SealedShare>,
    },
}

/// A share as a node lists it; the value stays sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfo {
    pub row: i64,
    pub share_id: String,
    pub name: String,
    /// Dealer's peer id.
    pub from: String,
    pub received_at: chrono::DateTime<Utc>,
}

/// Why a node refused a call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcError {
    /// Only `Request::Command` can be sent as a call.
    NotACommand,
    /// Only peers in `--allowclients` may call.
    NotAClient,
    Invalid(String),
    NotFound,
    /// No open challenge for this approver and request, or a wrong proof.
    BadProof,
    /// The node failed to handle the call.
    Internal,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotACommand => write!(f, "only commands can be sent"),
            Self::NotAClient => write!(f, "this peer is not an allowed client"),
            Self::Invalid(reason) => write!(f, "invalid call: {reason}"),
            Self::NotFound => write!(f, "not found"),
            Self::BadProof => write!(f, "wrong or expired approval proof"),
            Self::Internal => write!(f, "internal error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Command { id: u64, ts: u64, cmd: Command },
    Answer { id: u64, ts: u64, result: Response },
}

#[derive(Debug, Parser)]
#[command(version, about, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,

    /// Run a p2p node
    #[arg(long, requires = "allowclients")]
    node: bool,

    /// Client peer ids allowed to store, request, list and approve shares (comma separated)
    #[arg(long, value_delimiter = ',', requires = "node")]
    allowclients: Vec<PeerId>,

    /// Node peer ids allowed to connect; they can only ping (comma separated)
    #[arg(long, value_delimiter = ',', requires = "node")]
    allownodes: Vec<PeerId>,

    /// Key file created by `keygen`
    #[arg(long, default_value = "node.key")]
    key: PathBuf,

    /// SQLite database file, created and migrated on start
    #[arg(long, default_value = "asphalt.db")]
    db: PathBuf,

    /// This node's share public key, from `keygen --share`; approvers prove they hold its
    /// secret key
    #[arg(long, default_value = "share.pub")]
    share_pubkey: PathBuf,

    /// Address to listen on
    #[arg(long, default_value = "/ip4/0.0.0.0/udp/4433/quic-v1")]
    listen: Multiaddr,

    /// Nodes to stay connected to, as /ip4/<ip>/udp/<port>/quic-v1/p2p/<peer-id> (comma separated)
    #[arg(long, value_delimiter = ',', requires = "node")]
    connect: Vec<Multiaddr>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Generate a TLS key and print its peer id and public key, or with --share the keypair
    /// shares are encrypted to
    Keygen {
        /// Generate the share encryption keypair instead. The secret key is encrypted with a
        /// password read from stdin; only the public key goes to the node
        #[arg(long)]
        share: bool,
        /// Where to write the (secret) key [default: node.key, or share.key with --share]
        #[arg(long)]
        out: Option<PathBuf>,
        /// Where to write the share public key
        #[arg(long, default_value = "share.pub", requires = "share")]
        public: PathBuf,
        /// Overwrite existing key files
        #[arg(long)]
        force: bool,
    },
    /// Push, request, list, approve and restore secrets on the nodes in a client config
    Client(client::ClientArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(CliCommand::Keygen {
            share: false,
            out,
            force,
            ..
        }) => keys::keygen(&out.unwrap_or_else(|| "node.key".into()), force),
        Some(CliCommand::Keygen {
            share: true,
            out,
            public,
            force,
        }) => keys::share_keygen(&out.unwrap_or_else(|| "share.key".into()), &public, force),
        Some(CliCommand::Client(args)) => {
            init_tracing("warn");
            client::run(args).await
        }
        None if cli.node => {
            init_tracing("info");
            node::run(node::Options {
                key: cli.key,
                db: cli.db,
                share_pubkey: cli.share_pubkey,
                listen: cli.listen,
                allownodes: cli.allownodes,
                allowclients: cli.allowclients,
                connect: cli.connect,
            })
            .await
        }
        None => Ok(()),
    }
}

/// Logs to stderr, so a client's stdout carries only its output.
fn init_tracing(default: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .init();
}
