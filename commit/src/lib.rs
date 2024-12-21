use ark_ff::Field;
use std::ops::{Add, Mul};
use sumcheck::polynomials::MultiPoint;

mod committed_structure;
pub mod ipa;

pub trait CommmitmentScheme<F: Field> {
    type Commitment: for<'a> Add<&'a Self::Commitment, Output = Self::Commitment>
        + Mul<F, Output = Self::Commitment>
        + Clone;
    type OpenProof;

    fn new(vars: usize) -> Self;
    fn commit_mle(&self, evals: &[F]) -> Self::Commitment;
    /// returns (eval, proof), in case the eval is wanted
    fn open(
        &self,
        evals: &[F],
        commitment: Self::Commitment,
        point: &MultiPoint<F>,
        eval: Option<F>,
    ) -> (F, Self::OpenProof);
    fn verify(
        &self,
        commitment: Self::Commitment,
        point: &MultiPoint<F>,
        eval: F,
        proof: Self::OpenProof,
    ) -> bool;
}
