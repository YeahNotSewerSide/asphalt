//! Share encryption: HPKE sealing to share keys, dealer signatures and the approval proof.

use anyhow::Context as _;
use hpke::{Deserializable as _, Kem, OpModeR, OpModeS, Serializable as _, aead::ExportOnlyAead};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

// Shares are sealed with HPKE (RFC 9180). X-Wing (ML-KEM-768 + X25519) keeps stored shares safe
// against harvest-now-decrypt-later while staying at least as strong as X25519 alone.
pub type ShareKem = hpke::kem::XWing;
pub type ShareKdf = hpke::kdf::HkdfSha256;
pub type ShareAead = hpke::aead::ChaCha20Poly1305;
pub type SharePublicKey = <ShareKem as Kem>::PublicKey;
pub type ShareSecretKey = <ShareKem as Kem>::PrivateKey;

/// HPKE `info` for a share the dealer seals to the node that stores it.
pub const STORAGE_INFO: &[u8] = b"asphalt/share/v1";
/// HPKE `info` for a share the approver re-seals to the requester.
pub const DELIVERY_INFO: &[u8] = b"asphalt/delivery/v1";
const APPROVAL_INFO: &[u8] = b"asphalt/approval/v1";
const SIGNATURE_DOMAIN: &[u8] = b"asphalt/share-signature/v1";

/// Length-prefixed concatenation, so values can't shift across field boundaries.
pub fn fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

pub fn share_public_key(bytes: &[u8]) -> anyhow::Result<SharePublicKey> {
    SharePublicKey::from_bytes(bytes).map_err(|_| anyhow::anyhow!("invalid share public key"))
}

pub fn public_key_of(secret_key: &ShareSecretKey) -> SharePublicKey {
    ShareKem::sk_to_pk(secret_key)
}

/// A share sealed to a share public key. Nodes store and pass these on without being able to
/// open them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedShare {
    pub from: String,
    pub id: String,
    pub name: String,
    /// HPKE encapsulated key.
    #[serde(with = "hex")]
    pub enc: Vec<u8>,
    /// The `SharePayload`, sealed with the fields above (and a context) as associated data.
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
}

impl SealedShare {
    /// Seals `plaintext` to `key`. `context` is associated data on top of the metadata, such as
    /// who a delivery is for; opening needs the same `info` and `context`.
    pub fn seal(
        from: &str,
        id: &str,
        name: &str,
        plaintext: &[u8],
        key: &SharePublicKey,
        info: &[u8],
        context: &[u8],
    ) -> anyhow::Result<Self> {
        let (enc, ciphertext) = hpke::single_shot_seal::<ShareAead, ShareKdf, ShareKem>(
            &OpModeS::Base,
            key,
            info,
            plaintext,
            &Self::aad(from, id, name, context),
        )?;
        Ok(Self {
            from: from.into(),
            id: id.into(),
            name: name.into(),
            enc: enc.to_bytes().to_vec(),
            ciphertext,
        })
    }

    pub fn open(
        &self,
        key: &ShareSecretKey,
        info: &[u8],
        context: &[u8],
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let enc = <ShareKem as Kem>::EncappedKey::from_bytes(&self.enc)?;
        let plaintext = hpke::single_shot_open::<ShareAead, ShareKdf, ShareKem>(
            &OpModeR::Base,
            key,
            &enc,
            info,
            &self.ciphertext,
            &Self::aad(&self.from, &self.id, &self.name, context),
        )
        .map_err(|_| anyhow::anyhow!("share {} does not open with this key", self.id))?;
        Ok(Zeroizing::new(plaintext))
    }

    /// What a node can check without the secret key.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.id.is_empty(), "empty share id");
        <ShareKem as Kem>::EncappedKey::from_bytes(&self.enc)
            .map_err(|_| anyhow::anyhow!("invalid encapsulated key"))?;
        anyhow::ensure!(!self.ciphertext.is_empty(), "empty ciphertext");
        Ok(())
    }

    fn aad(from: &str, id: &str, name: &str, context: &[u8]) -> Vec<u8> {
        let mut aad = fields(&[from.as_bytes(), id.as_bytes(), name.as_bytes()]);
        aad.extend_from_slice(context);
        aad
    }
}

/// Associated data that binds a re-sealed share to the node it came from, the requester and the
/// request, so it can't be passed off as another delivery.
pub fn delivery_context(node: &str, requester: &str, request: i64) -> Vec<u8> {
    fields(&[
        node.as_bytes(),
        requester.as_bytes(),
        request.to_string().as_bytes(),
    ])
}

/// What a sealed share contains. Only clients see it: the dealer creates and signs it, the
/// approver and the requester open it.
#[derive(Serialize, Deserialize)]
pub struct SharePayload {
    pub x: u32,
    pub threshold: u32,
    /// Random id of the split this share belongs to; shares of different splits never combine.
    #[serde(with = "hex")]
    pub split: Vec<u8>,
    /// Share value, big-endian.
    #[serde(with = "hex")]
    pub y: Vec<u8>,
    /// Dealer's libp2p public key (protobuf); its peer id is the share's `from`.
    #[serde(with = "hex")]
    pub dealer: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

impl Drop for SharePayload {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl SharePayload {
    /// A share signed by `dealer`, whose peer id becomes the share's `from`. The signature stops
    /// anyone else holding the share public key, a node included, from forging a share.
    pub fn signed(
        dealer: &identity::Keypair,
        id: &str,
        name: &str,
        x: u32,
        threshold: u32,
        split: &[u8],
        y: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let from = dealer.public().to_peer_id().to_string();
        let mut payload = Self {
            x,
            threshold,
            split: split.to_vec(),
            y,
            dealer: dealer.public().encode_protobuf(),
            signature: Vec::new(),
        };
        payload.signature = dealer.sign(&payload.message(&from, id, name))?;
        Ok(payload)
    }

    /// Checks the dealer signature, and that the dealer is `from`.
    pub fn verify(&self, from: &str, id: &str, name: &str) -> anyhow::Result<()> {
        let dealer =
            identity::PublicKey::try_decode_protobuf(&self.dealer).context("invalid dealer key")?;
        anyhow::ensure!(
            dealer.to_peer_id().to_string() == from,
            "share {id} claims dealer {from} but is signed by {}",
            dealer.to_peer_id()
        );
        anyhow::ensure!(
            dealer.verify(&self.message(from, id, name), &self.signature),
            "share {id} has an invalid dealer signature"
        );
        Ok(())
    }

    pub fn to_bytes(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(serde_json::to_vec(self)?))
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes).context("invalid share payload")
    }

    fn message(&self, from: &str, id: &str, name: &str) -> Vec<u8> {
        fields(&[
            SIGNATURE_DOMAIN,
            from.as_bytes(),
            id.as_bytes(),
            name.as_bytes(),
            &self.x.to_be_bytes(),
            &self.threshold.to_be_bytes(),
            &self.split,
            &self.y,
        ])
    }
}

/// What an approval proof is bound to, so a proof for one approver, request and node is useless
/// for any other.
pub fn approval_context(
    node: &str,
    approver: &str,
    requester: &str,
    request: i64,
    share_id: &str,
) -> Vec<u8> {
    fields(&[
        node.as_bytes(),
        approver.as_bytes(),
        requester.as_bytes(),
        request.to_string().as_bytes(),
        share_id.as_bytes(),
    ])
}

/// Node side of the approval proof. X-Wing keys can't sign, so the node encapsulates to its own
/// share public key: only the holder of the secret key can derive the same exported secret from
/// `enc`. Returns `enc` for the approver and the proof it must send back.
pub fn approval_challenge(
    key: &SharePublicKey,
    context: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let (enc, sender) = hpke::setup_sender::<ExportOnlyAead, ShareKdf, ShareKem>(
        &OpModeS::Base,
        key,
        APPROVAL_INFO,
    )?;
    let mut proof = [0u8; 32];
    sender.export(context, &mut proof)?;
    Ok((enc.to_bytes().to_vec(), proof))
}

/// Client side of the approval proof; needs the share secret key.
pub fn approval_proof(
    key: &ShareSecretKey,
    enc: &[u8],
    context: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let enc = <ShareKem as Kem>::EncappedKey::from_bytes(enc)?;
    let receiver = hpke::setup_receiver::<ExportOnlyAead, ShareKdf, ShareKem>(
        &OpModeR::Base,
        key,
        &enc,
        APPROVAL_INFO,
    )?;
    let mut proof = [0u8; 32];
    receiver.export(context, &mut proof)?;
    Ok(proof)
}

pub fn proof_matches(expected: &[u8; 32], proof: &[u8]) -> bool {
    bool::from(expected.as_slice().ct_eq(proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(dealer: &identity::Keypair) -> SharePayload {
        SharePayload::signed(dealer, "secret-1", "test", 2, 2, &[9; 16], vec![7; 256]).unwrap()
    }

    #[test]
    fn sealed_share_opens_only_with_its_key_and_metadata() {
        let (secret_key, public_key) = ShareKem::gen_keypair();
        let (other_secret_key, _) = ShareKem::gen_keypair();
        let sealed = SealedShare::seal(
            "dealer",
            "secret-1",
            "test",
            b"value",
            &public_key,
            STORAGE_INFO,
            &[],
        )
        .unwrap();

        assert_eq!(
            *sealed.open(&secret_key, STORAGE_INFO, &[]).unwrap(),
            b"value"
        );
        assert!(sealed.open(&other_secret_key, STORAGE_INFO, &[]).is_err());
        assert!(sealed.open(&secret_key, DELIVERY_INFO, &[]).is_err());
        assert!(sealed.open(&secret_key, STORAGE_INFO, b"context").is_err());
        let mut moved = sealed.clone();
        moved.id = "secret-2".into();
        assert!(moved.open(&secret_key, STORAGE_INFO, &[]).is_err());
    }

    #[test]
    fn payload_signature_binds_dealer_and_contents() {
        let dealer = identity::Keypair::generate_ed25519();
        let from = dealer.public().to_peer_id().to_string();
        let payload = payload(&dealer);
        payload.verify(&from, "secret-1", "test").unwrap();

        assert!(payload.verify(&from, "secret-2", "test").is_err());
        let other = identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_string();
        assert!(payload.verify(&other, "secret-1", "test").is_err());
        let mut forged = SharePayload::from_bytes(&payload.to_bytes().unwrap()).unwrap();
        forged.y[0] ^= 1;
        assert!(forged.verify(&from, "secret-1", "test").is_err());
    }

    #[test]
    fn approval_proof_needs_the_secret_key_and_context() {
        let (secret_key, public_key) = ShareKem::gen_keypair();
        let (other_secret_key, _) = ShareKem::gen_keypair();
        let context = approval_context("node", "approver", "requester", 1, "secret-1");
        let (enc, expected) = approval_challenge(&public_key, &context).unwrap();

        let proof = approval_proof(&secret_key, &enc, &context).unwrap();
        assert!(proof_matches(&expected, &proof));
        let wrong_key = approval_proof(&other_secret_key, &enc, &context).unwrap();
        assert!(!proof_matches(&expected, &wrong_key));
        let other_approver = approval_context("node", "other", "requester", 1, "secret-1");
        let wrong_context = approval_proof(&secret_key, &enc, &other_approver).unwrap();
        assert!(!proof_matches(&expected, &wrong_context));
        assert!(!proof_matches(&expected, &proof[..31]));
    }
}
