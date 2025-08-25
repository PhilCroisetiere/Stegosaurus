use secrecy::SecretString;
use zeroize::Zeroizing;
use rand_core::RngCore;
use argon2::{
    Algorithm, Argon2, Params, Version
}; 
use hkdf::Hkdf;
use sha2::Sha256;
use secrecy::ExposeSecret;


#[derive(Debug)]
pub enum CryptoError {
    InvalidArgon2Params,
    Argon2HashFailed,
    HkdfExpandInvalidLen,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidArgon2Params => write!(f, "invalid Argon2 parameters"),
            CryptoError::Argon2HashFailed => write!(f, "Argon2 hashing failed"),
            CryptoError::HkdfExpandInvalidLen => write!(f, "HKDF expansion invalid length"),
        }
    }
}
impl std::error::Error for CryptoError {}


pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

pub struct PassphrasePrimitives {
    pub salt: [u8; 16],
    pub root: Zeroizing<[u8; 32]>,
}

pub struct Keys {
    pub enc_key: Zeroizing<[u8; 32]>,
    pub prng_key: Zeroizing<[u8; 32]>,
}

fn argon2_derive_32(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<[u8; 32], CryptoError> {
    let argon2_params =
        Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
            .map_err(|_| CryptoError::InvalidArgon2Params)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|_| CryptoError::Argon2HashFailed)?;

    Ok(output)
}

/// Derives a 32-byte encryption root key from a passphrase using Argon2id.
/// The salt is randomly generated with hardware and should be stored alongside the encrypted data.
/// # Parameters
/// - `passphrase`: The user's passphrase as a `SecretString`.
/// # Returns
/// A 32-byte array representing the derived encryption root key.
pub fn passphrase_to_root_and_salt(
    passphrase: &SecretString,
    params: Argon2Params,
) -> Result<PassphrasePrimitives, CryptoError> {
    let mut salt = [0u8; 16];
    // Use rng() instead of thread_rng()
    rand::rng().fill_bytes(&mut salt);

    let root = argon2_derive_32(passphrase.expose_secret().as_bytes(), &salt, params)?;
    Ok(PassphrasePrimitives {
        root: Zeroizing::new(root),
        salt,
    })
}

/// Expands a key using HKDF with SHA-256.
/// # Parameters
/// - `key`: The input key material.
/// - `info`: Contextual information for the expansion.
/// # Returns
/// A 32-byte array representing the expanded key.
fn hkdf_expand(key: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::HkdfExpandInvalidLen)?;
    Ok(okm)
}

pub fn key_generation(root: &Zeroizing<[u8; 32]>) -> Result<Keys, CryptoError> {
    let enc_key  = hkdf_expand(root.as_ref(), b"enc")?;
    let prng_key = hkdf_expand(root.as_ref(), b"prng")?;

    Ok(Keys {
        enc_key: Zeroizing::new(enc_key),
        prng_key: Zeroizing::new(prng_key),
    })
}