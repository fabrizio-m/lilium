use ark_ff::Field;
use sponge::sponge::Duplex;
use std::{
    fmt::Debug,
    ops::{Add, Mul},
};
use sumcheck::polynomials::MultiPoint;
use transcript::{protocols::Protocol, Message, Transcript};

pub mod committed_structure;
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

#[derive(Debug, Clone)]
pub struct OpenInstance<F: Field, G> {
    commit: G,
    point: MultiPoint<F>,
    eval: F,
}

impl<F: Field, G> Message<F> for OpenInstance<F, G>
where
    G: Message<F>,
{
    fn len(vars: usize, param_resolver: &transcript::params::ParamResolver) -> usize {
        let commit = G::len(vars, param_resolver);
        commit + vars + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = Vec::with_capacity(4 + self.point.vars() + 1);
        elems.extend(self.commit.to_field_elements());
        elems.extend(self.point.clone().inner());
        elems.push(self.eval);
        elems
    }
}
pub trait CommmitmentScheme2<F: Field>: Protocol<F>
where
    Self: Protocol<
        F,
        Key = Self,
        Instance = OpenInstance<F, Self::Commitment>,
        Proof = Self::OpenProof,
    >,
{
    type Commitment: for<'a> Add<&'a Self::Commitment, Output = Self::Commitment>
        + Mul<F, Output = Self::Commitment>
        + Clone;
    type OpenProof: Debug;

    fn new(vars: usize) -> Self;
    fn commit_mle(&self, evals: &[F]) -> Self::Commitment;
    /// Creates an open instance for a given commitment on a given point.
    /// The instance can be proved and verified together with the proof.
    fn open_instance(
        &self,
        commitment: Self::Commitment,
        point: MultiPoint<F>,
        evals: &[F],
    ) -> OpenInstance<F, Self::Commitment>;
    /// Proves the instance
    fn open_prove<S: Duplex<F>>(
        &self,
        instance: OpenInstance<F, Self::Commitment>,
        evals: &[F],
        transcript: &mut Transcript<F, S>,
    ) -> Result<Self::OpenProof, Self::Error>;
}
