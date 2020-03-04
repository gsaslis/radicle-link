use std::{
    fmt::{self, Display},
    ops::Deref,
    time::SystemTime,
};

use ::pgp::conversions::Time;
use bs58;
use hex::decode;
use secstr::SecStr;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::sign;

use keystore::SecretKeyExt;

use crate::keys::pgp;

/// A device-specific signing key
#[derive(Clone, Eq, PartialEq)]
pub struct Key {
    sk: sign::SecretKey,
    /// Time this key was created, normalised seconds precision.
    created_at: SystemTime,
}

/// The public part of a `Key``
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PublicKey(sign::PublicKey);

/// A signature produced by `Key::sign`
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Signature(sign::Signature);

// Key

impl Key {
    pub fn new() -> Self {
        let (_, sk) = sign::gen_keypair();
        let created_at = SystemTime::now().canonicalize();
        Key { sk, created_at }
    }

    #[cfg(test)]
    pub fn from_seed(seed: &sign::Seed, created_at: SystemTime) -> Self {
        let (_, sk) = sign::keypair_from_seed(seed);
        Key {
            sk,
            created_at: created_at.canonicalize(),
        }
    }

    pub(crate) fn from_secret(sk: sign::SecretKey, created_at: SystemTime) -> Self {
        Key {
            sk,
            created_at: created_at.canonicalize(),
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.sk.public_key())
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        Signature(sign::sign_detached(data, &self.sk))
    }

    pub fn into_pgp(
        self,
        nickname: &str,
        fullname: Option<String>,
    ) -> Result<pgp::Key, pgp::Error> {
        let uid = pgp::UserID::from_address(fullname, None, format!("{}@{}", nickname, self))
            .expect("messed up UserID");
        pgp::Key::from_sodium(&self.sk, uid, self.created_at)
    }
}

impl Default for Key {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.public().fmt(f)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.sk.as_ref()
    }
}

#[derive(Debug)]
pub enum IntoSecretKeyError {
    InvalidSliceLength,
}

impl Display for IntoSecretKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidSliceLength => f.write_str("Invalid slice length"),
        }
    }
}

impl SecretKeyExt for Key {
    type Metadata = SystemTime;
    type Error = IntoSecretKeyError;

    fn from_bytes_and_meta(bytes: SecStr, metadata: &Self::Metadata) -> Result<Self, Self::Error> {
        let sk = sign::SecretKey::from_slice(bytes.unsecure())
            .ok_or(IntoSecretKeyError::InvalidSliceLength)?;
        Ok(Self::from_secret(sk, *metadata))
    }

    fn metadata(&self) -> Self::Metadata {
        self.created_at
    }
}

// PublicKey

impl PublicKey {
    pub fn verify(&self, sig: &Signature, data: &[u8]) -> bool {
        sign::verify_detached(sig, &data, self)
    }

    pub fn from_slice(bs: &[u8]) -> Option<PublicKey> {
        sign::PublicKey::from_slice(&bs).map(PublicKey)
    }
}

impl From<sign::PublicKey> for PublicKey {
    fn from(pk: sign::PublicKey) -> Self {
        Self(pk)
    }
}

impl From<Key> for PublicKey {
    fn from(k: Key) -> Self {
        k.public()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            bs58::encode(self)
                .with_alphabet(bs58::alphabet::BITCOIN)
                .into_string()
        )
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for PublicKey {
    type Target = sign::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Signature

impl Signature {
    pub fn verify(&self, data: &[u8], pk: &PublicKey) -> bool {
        sign::verify_detached(self, &data, pk)
    }

    pub fn from_hex_string(s: &str) -> Result<Self, failure::Error> {
        let bytes =
            decode(s).map_err(|_| failure::format_err!("Cannot decode signature hex string"))?;
        let buffer = if bytes.len() == 64 {
            let mut buffer = [0u8; 64];
            for (i, v) in bytes.iter().enumerate() {
                buffer[i] = *v;
            }
            buffer
        } else {
            return Err(failure::format_err!(
                "Signature buffer has length {} instead of 64",
                bytes.len()
            ));
        };
        Ok(Self(sodiumoxide::crypto::sign::Signature(buffer)))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for Signature {
    type Target = sign::Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const DATA_TO_SIGN: &[u8] = b"alors monsieur";

    #[test]
    fn test_sign_verify_via_signature() {
        let key = Key::new();
        let sig = key.sign(&DATA_TO_SIGN);
        assert!(sig.verify(&DATA_TO_SIGN, &key.public()))
    }

    #[test]
    fn test_sign_verify_via_pubkey() {
        let key = Key::new();
        let sig = key.sign(&DATA_TO_SIGN);
        assert!(key.public().verify(&sig, &DATA_TO_SIGN))
    }
}