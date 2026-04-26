use ark_ff::Field;
use sponge::sponge::Duplex;
use std::{
    fmt::Debug,
    ops::{Add, Mul},
};
use sumcheck::polynomials::MultiPoint;
use transcript::{protocols::Protocol, Message, Transcript};

pub mod batching;
pub mod committed_structure;
pub mod ipa;

#[derive(Debug, Clone)]
pub struct OpenInstance<F: Field, G> {
    commit: G,
    point: MultiPoint<F>,
    eval: F,
}

impl<F: Field, G> OpenInstance<F, G> {
    pub fn new(commit: G, point: MultiPoint<F>, eval: F) -> Self {
        Self {
            commit,
            point,
            eval,
        }
    }

    /// Claimed evaluation at the given point.
    pub fn eval(&self) -> F {
        self.eval
    }
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
pub trait CommmitmentScheme<F: Field>: Protocol<F> + Debug + Clone
where
    Self: Protocol<
        F,
        Key = Self,
        Instance = OpenInstance<F, Self::Commitment>,
        Proof = Self::OpenProof,
    >,
{
    type Commitment: for<'a> Add<&'a Self::Commitment, Output = Self::Commitment>
        + Add<Output = Self::Commitment>
        + Mul<F, Output = Self::Commitment>
        + Clone
        + Debug
        + Message<F>;
    type OpenProof: Debug + Clone;

    fn new(vars: usize) -> Self;
    fn commit_mle(&self, evals: &[F]) -> Self::Commitment;
    /// Specialized case of commit where all evaluations belong to a set of 256 elements.
    /// Something many schemes can take advantage of for considerable optimization.
    fn commit_small_set(&self, evals: &[u8], set: [F; 256]) -> Self::Commitment {
        let evals: Vec<F> = evals.iter().map(|i| set[*i as usize]).collect();
        self.commit_mle(evals.as_slice())
    }
    /// Further specialized version of [Self::commit_small_set], where the set is
    /// [0..256].
    fn commit_bytes(&self, evals: &[u8]) -> Self::Commitment {
        let set: Vec<F> = (0..256).map(|i| F::from(i as u8)).collect();
        let set: [F; 256] = set.try_into().unwrap();
        self.commit_small_set(evals, set)
    }
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
