//! Key files: the TLS identity, and the share keypair whose secret key is stored encrypted with a
//! password.

use std::{
    fs, io,
    io::{IsTerminal as _, Write as _},
    path::Path,
};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead as _, KeyInit as _, Payload},
};
use anyhow::Context as _;
use argon2::{Algorithm, Argon2, Params, Version};
use hpke::{Deserializable as _, Kem as _, Serializable as _};
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{ShareKem, SharePublicKey, ShareSecretKey};

/// Generates an ed25519 identity. libp2p's QUIC transport uses it to sign the TLS certificate,
/// and the peer id is derived from its public key.
pub fn keygen(out: &Path, force: bool) -> anyhow::Result<()> {
    let keypair = Keypair::generate_ed25519();
    create_key_file(out, force)?.write_all(&keypair.to_protobuf_encoding()?)?;

    let public = keypair.public();
    println!("key file:   {}", out.display());
    println!("peer id:    {}", public.to_peer_id());
    println!(
        "public key: {}",
        hex::encode(public.clone().try_into_ed25519()?.to_bytes())
    );
    Ok(())
}

/// Generates the keypair shares are sealed to. It is unrelated to the TLS identity, and its
/// secret key is only written encrypted with a password.
pub fn share_keygen(secret: &Path, public: &Path, force: bool) -> anyhow::Result<()> {
    // Fail before asking for a password that would go unused.
    if !force {
        for path in [secret, public] {
            anyhow::ensure!(
                !path.exists(),
                "{} already exists (use --force to overwrite)",
                path.display()
            );
        }
    }
    let password = read_new_password()?;

    let (secret_key, public_key) = ShareKem::gen_keypair();
    let encrypted = EncryptedKeyFile::encrypt(&secret_key.to_bytes(), &password)?;

    let mut secret_file = create_key_file(secret, force)?;
    let mut public_file = match create_key_file(public, force) {
        Ok(file) => file,
        Err(e) => {
            let _ = fs::remove_file(secret);
            return Err(e);
        }
    };
    serde_json::to_writer_pretty(&mut secret_file, &encrypted)?;
    secret_file.write(b"\n")?;
    writeln!(public_file, "{}", hex::encode(public_key.to_bytes()))?;

    println!(
        "secret key: {} (password-encrypted, keep it off the node)",
        secret.display()
    );
    println!(
        "public key: {} (pass to the node with --share-pubkey)",
        public.display()
    );
    Ok(())
}

/// Reads the password for a new secret key file. On a terminal it is typed twice without echo;
/// otherwise a single line is read from stdin, so scripts can pipe it in.
fn read_new_password() -> anyhow::Result<Zeroizing<String>> {
    let password = if io::stdin().is_terminal() {
        let password = Zeroizing::new(rpassword::prompt_password("password: ")?);
        let repeated = Zeroizing::new(rpassword::prompt_password("repeat password: ")?);
        anyhow::ensure!(*password == *repeated, "passwords do not match");
        password
    } else {
        read_stdin_line()?
    };
    anyhow::ensure!(!password.is_empty(), "password must not be empty");
    Ok(password)
}

/// Reads the password of an existing key file, the same way as `read_new_password` but once.
fn read_password(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    } else {
        Ok(read_stdin_line()?)
    }
}

fn read_stdin_line() -> io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    io::stdin().read_line(&mut line)?;
    let len = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(len);
    Ok(line)
}

// Argon2id cost for password-encrypted key files: RFC 9106's second recommended option (64 MiB,
// 3 passes), with one lane since the argon2 crate hashes on a single thread.
const KEY_FILE_M_COST: u32 = 64 * 1024;
const KEY_FILE_T_COST: u32 = 3;
const KEY_FILE_P_COST: u32 = 1;

/// AES-GCM associated data for key files; bump the version if the format changes.
const KEY_FILE_AAD: &[u8] = b"asphalt/key-file/v1";

/// A secret key encrypted with AES-256-GCM under a key that Argon2id derives from a password.
/// The Argon2id parameters are stored so they can be raised later without breaking old files.
#[derive(Serialize, Deserialize)]
struct EncryptedKeyFile {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    #[serde(with = "hex")]
    salt: Vec<u8>,
    #[serde(with = "hex")]
    nonce: Vec<u8>,
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
}

impl EncryptedKeyFile {
    fn encrypt(secret: &[u8], password: &str) -> anyhow::Result<Self> {
        let salt: [u8; 16] = rand::random();
        let nonce: [u8; 12] = rand::random();
        let cipher = Self::cipher(
            password,
            &salt,
            KEY_FILE_M_COST,
            KEY_FILE_T_COST,
            KEY_FILE_P_COST,
        )?;
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: secret,
                    aad: KEY_FILE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt key"))?;
        Ok(Self {
            m_cost: KEY_FILE_M_COST,
            t_cost: KEY_FILE_T_COST,
            p_cost: KEY_FILE_P_COST,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn decrypt(&self, password: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let nonce: [u8; 12] = self.nonce.as_slice().try_into().context("invalid nonce")?;
        let cipher = Self::cipher(password, &self.salt, self.m_cost, self.t_cost, self.p_cost)?;
        let secret = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &self.ciphertext,
                    aad: KEY_FILE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("wrong password or corrupted key file"))?;
        Ok(Zeroizing::new(secret))
    }

    fn cipher(
        password: &str,
        salt: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> anyhow::Result<Aes256Gcm> {
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(m_cost, t_cost, p_cost, Some(key.len()))?,
        )
        .hash_password_into(password.as_bytes(), salt, key.as_mut())?;
        Ok(Aes256Gcm::new(&(*key).into()))
    }
}

/// Creates `path` readable only by its owner. Refuses to replace an existing file unless `force`.
pub fn create_key_file(path: &Path, force: bool) -> anyhow::Result<fs::File> {
    if force {
        match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).with_context(|| {
        format!(
            "failed to create {} (use --force to overwrite)",
            path.display()
        )
    })
}

pub fn load_keypair(path: &Path) -> anyhow::Result<Keypair> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read {} (run `asphalt keygen` first)",
            path.display()
        )
    })?;
    Ok(Keypair::from_protobuf_encoding(&bytes)?)
}

pub fn load_share_public_key(path: &Path) -> anyhow::Result<SharePublicKey> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read {} (run `asphalt keygen --share` first)",
            path.display()
        )
    })?;
    let bytes = hex::decode(text.trim())
        .with_context(|| format!("{} is not a hex public key", path.display()))?;
    Ok(SharePublicKey::from_bytes(&bytes)?)
}

/// Loads a share secret key, asking for the password it is encrypted with.
pub fn load_share_secret_key(path: &Path) -> anyhow::Result<ShareSecretKey> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: EncryptedKeyFile = serde_json::from_str(&text)
        .with_context(|| format!("{} is not an encrypted key file", path.display()))?;
    let password = read_password(&format!("password for {}: ", path.display()))?;
    let secret = file.decrypt(&password)?;
    Ok(ShareSecretKey::from_bytes(&secret)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_decrypts_only_with_its_password() {
        let secret = [7u8; 32];
        let file = EncryptedKeyFile::encrypt(&secret, "correct horse").unwrap();
        assert_eq!(*file.decrypt("correct horse").unwrap(), secret);
        assert!(file.decrypt("wrong horse").is_err());
    }

    #[test]
    fn encrypted_share_key_round_trips() {
        let (secret_key, public_key) = ShareKem::gen_keypair();
        let encrypted = EncryptedKeyFile::encrypt(&secret_key.to_bytes(), "pw").unwrap();
        let file: EncryptedKeyFile =
            serde_json::from_str(&serde_json::to_string(&encrypted).unwrap()).unwrap();
        let secret_key = ShareSecretKey::from_bytes(&file.decrypt("pw").unwrap()).unwrap();
        assert_eq!(
            crate::crypto::public_key_of(&secret_key).to_bytes(),
            public_key.to_bytes()
        );
    }
}
