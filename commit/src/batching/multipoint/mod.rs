use std::marker::PhantomData;

mod evals;
mod prove;
mod reduction;
mod sumcheck;

pub use prove::ProverOutput;

/// A reduction allowing to batch opening proofs over different points.
#[derive(Clone, Copy, Debug)]
pub struct MultipointBatching<C, const N: usize>(PhantomData<C>);

impl<C, const N: usize> Default for MultipointBatching<C, N> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MultipointEvals<V> {
    eq: V,
    poly: V,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum MultipointIdx {
    Eq,
    Poly,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MultipointChall<F>(F);
