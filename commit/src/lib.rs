use ark_ff::Field;
use std::ops::{Add, Mul};
use sumcheck::polynomials::MultiPoint;

pub mod ipa;

pub trait CommmitmentScheme<F: Field> {
    type Commitment: for<'a> Add<&'a Self::Commitment, Output = Self::Commitment>
        + Mul<F, Output = Self::Commitment>;
    type OpenProof;

    fn new(vars: usize) -> Self;
    fn commit_mle(&self, evals: &[F]) -> Self::Commitment;
    fn open(
        &self,
        evals: &[F],
        commitment: Self::Commitment,
        point: &MultiPoint<F>,
        eval: Option<F>,
    ) -> Self::OpenProof;
    fn verify(
        &self,
        commitment: Self::Commitment,
        point: &MultiPoint<F>,
        eval: F,
        proof: Self::OpenProof,
    ) -> bool;
}
