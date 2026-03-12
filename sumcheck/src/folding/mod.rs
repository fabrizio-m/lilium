use crate::{
    barycentric_eval::BarycentricWeights,
    message::Message,
    sumcheck::{Sum, SumcheckFunction, SumcheckProver},
    symbolic::sumcheck_eval::SumcheckEvaluator,
};
use ark_ff::Field;
use transcript::params::ParamResolver;

mod prover;
mod reduction;
#[cfg(test)]
mod tests;
pub mod utils;
#[cfg(test)]
mod zerocheck;
mod zerofold;

pub use prover::SumFoldProverOutput;
pub use zerofold::ZeroFold;

/// Reduction from 2 folding instances into a single one.
pub struct SumFold<F: Field, SF: SumcheckFunction<F>> {
    // Weights for degree d.
    weights: BarycentricWeights<F>,
    // Weights for degree d + 1.
    extended_weights: BarycentricWeights<F>,
    degree: usize,
    evaluator: SumcheckEvaluator<F, SF>,
}

impl<F: Field, SF: SumcheckFunction<F>> SumFold<F, SF> {
    pub fn new(f: &SF) -> Self {
        let degree = SumcheckProver::<F, SF>::degree_symbolic(f);
        Self::new_custom_degree(degree, f)
    }

    pub(super) fn new_custom_degree(degree: usize, f: &SF) -> Self {
        let evaluator = SumcheckEvaluator::new(Some(f));
        let weights = BarycentricWeights::compute(degree as u32);
        let extended_weights = BarycentricWeights::compute(degree as u32 + 1);
        Self {
            weights,
            extended_weights,
            degree,
            evaluator,
        }
    }
}

pub struct SumFoldProof<F: Field> {
    message: Message<F>,
}

pub struct SumFoldInstance<F, const N: usize> {
    sums: [Sum<F>; N],
}

impl<F, const N: usize> SumFoldInstance<F, N> {
    pub fn new(sums: [F; N]) -> Self {
        let sums = sums.map(Sum);
        Self { sums }
    }
}

impl<F: Field, const N: usize> transcript::Message<F> for SumFoldInstance<F, N> {
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        <[Sum<F>; N] as transcript::Message<F>>::len(vars, param_resolver)
    }

    fn to_field_elements(&self) -> Vec<F> {
        self.sums.to_field_elements()
    }
}
