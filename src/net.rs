//! The libp2p setup shared by nodes and clients: QUIC with TLS 1.3, an allowlist, pings and the
//! request-response protocol.

use std::time::Duration;

use libp2p::{
    PeerId, Swarm, SwarmBuilder, allow_block_list,
    identity::Keypair,
    ping,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
};

use crate::{PROTOCOL, Request, Response, RpcError};

const PING_INTERVAL: Duration = Duration::from_secs(10);

pub type RpcReply = Result<Response, RpcError>;

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    allowlist: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    pub ping: ping::Behaviour,
    pub rpc: request_response::cbor::Behaviour<Request, RpcReply>,
}

/// A swarm for `identity` that only talks to `allowed` peers. Connections close after
/// `idle_timeout` without traffic.
pub fn swarm(
    identity: Keypair,
    allowed: impl IntoIterator<Item = PeerId>,
    idle_timeout: Duration,
) -> anyhow::Result<Swarm<Behaviour>> {
    let mut allowlist = allow_block_list::Behaviour::default();
    for peer in allowed {
        allowlist.allow_peer(peer);
    }
    let behaviour = Behaviour {
        allowlist,
        ping: ping::Behaviour::new(ping::Config::new().with_interval(PING_INTERVAL)),
        rpc: request_response::cbor::Behaviour::new(
            [(PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
    };

    Ok(SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(idle_timeout))
        .build())
}
