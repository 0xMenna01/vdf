// In the following RSA group construction we use 2048 bit key size;
// The RSA construction is not the same as the one for singing, but is specific
// to be used as a group of unknown order for the VDF
// Note that this will be mainly used in the context of ink based smart contracts,
// so data types must be easily stored.
// ink custom data structures: https://use.ink/datastructures/custom-datastructure

use crate::{Vec, VDFSetupSecret};
use crate::{VDFPublicParam, VDFSecretParam};
use crypto_bigint::{Encoding, Wrapping, U2048};

const KEY_LENGTH: usize = 256;

#[derive(Debug, Clone, Copy)]
struct RSASecretKey([u8; KEY_LENGTH]);

#[derive(Debug, Clone, Copy)]
struct RSAPublicKey([u8; KEY_LENGTH]);

type Integer = U2048;

#[derive(Debug, Clone, Copy)]
struct BigInteger(Integer);
struct Totient;

impl BigInteger {
    /// Wraps the integer to perform arithmetic operations
    fn wrap(&self) -> Wrapping<Integer> {
        Wrapping(self.0)
    }
    /// Subtract 1 to the given integer
    fn subtract_one(&self) -> Self {
        BigInteger((self.wrap() - Wrapping(Integer::ONE)).0)
    }
    /// Performs the conversion of the integer to a big endian byte array
    fn to_bytes(&self) -> [u8; KEY_LENGTH] {
        self.0.to_be_bytes()
    }
}

/// Obtains the integer associated to a given RSA secret key
impl From<RSASecretKey> for BigInteger {
    fn from(secret_key: RSASecretKey) -> Self {
        BigInteger(Integer::from_be_slice(secret_key.0.as_ref()))
    }
}

/// Obtains the integer associated to a given RSA public key
impl From<RSAPublicKey> for BigInteger {
    fn from(pubkey: RSAPublicKey) -> Self {
        BigInteger(Integer::from_be_slice(pubkey.0.as_ref()))
    }
}

/// Implemnets the totient operation, given two primes: op: (p-1)(q-1)
impl Totient {
    fn from_primes(prime1: BigInteger, prime2: BigInteger) -> BigInteger {
        BigInteger((prime1.subtract_one().wrap() - prime2.subtract_one().wrap()).0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RSASecretParam {
    /// First Big prime
    p: BigInteger,
    /// Second Big prime
    q: BigInteger,
}

// Implements the trait for the VDF
impl VDFSecretParam for RSASecretParam {
    fn to_vec(&self) -> Vec<u8> {
        RSASecretKey::from(self.clone()).0.to_vec()
    }
}

/// Obtains the byte array secret key from the RSA secret parameters
impl From<RSASecretParam> for RSASecretKey {
    fn from(secret_param: RSASecretParam) -> Self {
        let totient = Totient::from_primes(secret_param.p, secret_param.q);
        Self(totient.to_bytes())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RSAPublicParam {
    /// RSA Modulus
    n: BigInteger,
}

// Implements the trait for the VDF
impl VDFPublicParam for RSAPublicParam {
    fn to_vec(&self) -> Vec<u8> {
        RSAPublicKey::from(self.clone()).0.to_vec()
    }
}

/// Obtains the byte array public key from the RSA public parameters
impl From<RSAPublicParam> for RSAPublicKey {
    fn from(public_param: RSAPublicParam) -> Self {
        Self(public_param.n.to_bytes())
    }
}

// These secret parameters are used to perform a KDF to obtain unpredictable big integer values.
// The first two values that pass the primality test are being assigned to the private parameters.
pub struct RSASetupSecret {
    secret_seed: Vec<u8>,
    salt: Vec<u8>,
}

impl VDFSetupSecret for RSASetupSecret {}

pub struct RSA {
    secret_param: RSASecretParam,
    public_param: RSAPublicParam,
}

impl RSA {
    pub fn setup(secret: RSASetupSecret) -> Self {
        todo!()
    }
}
