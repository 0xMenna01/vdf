use self::rsa::{BigInteger, BytesWrapper};
use super::Vec;
use anyhow::{Error, Result};
use ring::hkdf;

pub mod rsa;

/// Generic newtype wrapper that lets us implement traits for externally-defined
/// types.
///
/// Refer to https://github.com/briansmith/ring/blob/main/tests/hkdf_tests.rs
#[derive(Debug, PartialEq)]
struct My<T: core::fmt::Debug + PartialEq>(T);

impl hkdf::KeyType for My<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<hkdf::Okm<'_, My<usize>>> for My<Vec<u8>> {
    fn from(okm: hkdf::Okm<My<usize>>) -> Self {
        let mut r = vec![0_u8; okm.len().0];
        okm.fill(&mut r).unwrap();
        Self(r)
    }
}

/// PRNG used to perform a generation of a pseudorandom Big integer value
pub struct CustomPRNG<const LENGTH: usize> {
    /// Secure cryptographic algorithm being used
    algorithm: hkdf::Algorithm,
    /// Key material to perform the KDF
    secret_key: Vec<u8>,
}

impl<const LENGTH: usize> CustomPRNG<LENGTH> {
    pub fn new(algorithm: hkdf::Algorithm, secret_key: &[u8]) -> Self {
        let secret_key = secret_key.to_vec();

        Self {
            algorithm,
            secret_key,
        }
    }

    pub fn from_salt(&self, salt: &[u8]) -> Result<BigInteger, HKDFExpandError> {
        let info = vec![b"Expanging key to obtain a big pseudorandom integer".as_slice()];
        
        let salt = hkdf::Salt::new(self.algorithm, salt);
        let prk = salt.extract(&self.secret_key.as_slice());

        let okm = prk
            .expand(info.as_slice(), My(LENGTH))
            .map_err(|_| HKDFExpandError::from(anyhow::anyhow!("KDF expansion error")))?;

        let mut seed = [0_u8; LENGTH];
        okm.fill(seed.as_mut())
            .map_err(|_| HKDFExpandError::from(anyhow::anyhow!("KDF expansion error")))?;

        let bytes_wrap = BytesWrapper(seed);

        let integer = BigInteger::from(bytes_wrap);

        Ok(integer)
    }
}

#[derive(Debug)]
pub struct HKDFExpandError {
    message: String,
}

impl From<Error> for HKDFExpandError {
    fn from(error: Error) -> Self {
        Self {
            message: format!("{error:?}"),
        }
    }
}
