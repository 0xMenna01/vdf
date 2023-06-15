#![cfg_attr(not(feature = "std"), no_std)]
#![feature(min_specialization)]

use ink::prelude::vec::Vec as InkVec;

mod groups;

// The code provided refers to the Efficient verifiable delay function of Wesolowski
// paper: https://eprint.iacr.org/2018/623.pdf

type Vec<T> = InkVec<T>;

//The following traits must be implemented by the specific VDF of a certain unknown group
pub trait VDFPublicParam {
    /// Converts public key as array of bytes
    fn to_vec(&self) -> Vec<u8>;
}
pub trait VDFSecretParam {
    /// Converts public key as array of bytes
    fn to_vec(&self) -> Vec<u8>;
}
pub trait VDFOutProof {}
pub trait VDFSetupSecret {}

pub trait VDF {
    /// Given a group G of unknown order, stores the public key and the order of the group (private key) and returns self
    fn setup<T: AsRef<[u8]>>(secret_seed: dyn VDFSetupSecret, delta: usize) -> Self;

    /// Given the private key it computes efficiently the VDF output and a proof
    fn trapdoor<T: AsRef<[u8]>>(&self, x: T, delta: usize) -> dyn VDFOutProof;

    /// VDF Evaluation function Uses the public key to compute the VDF output sequentially
    fn evaluation<T: AsRef<[u8]>>(&self, x: T) -> dyn VDFOutProof;

    /// VDF Verification
    fn verify<T: AsRef<[u8]>>(&self, x: T, y: T, pi: T) -> bool;
}
