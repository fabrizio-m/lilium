use ark_ff::Field;
use commit::CommmitmentScheme;
use sumcheck::{folding::utils::FieldFolder, zerocheck::CompactPowers};
use transcript::{params::ParamResolver, Message};

mod folding;
mod key;
mod reduction;
mod reduction_proving;
mod sumcheck_reduction;

pub use key::FlcsReductionKey;
pub use reduction::{FlcsReduction, FlcsReductionProof};
pub use reduction_proving::ReducedInstanceWitness;

#[derive(Clone, Debug)]
/// LCS instance which can be folded.
pub struct FoldableLcsInstance<F, C, const I: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    witness_commit: C::Commitment,
    public_inputs: [F; I],
    zerocheck_powers: CompactPowers<F>,
    sum: F,
}

impl<F, C, const I: usize> FoldableLcsInstance<F, C, I>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub(crate) fn new(
        witness_commit: C::Commitment,
        public_inputs: [F; I],
        zerocheck_powers: CompactPowers<F>,
    ) -> Self {
        Self {
            witness_commit,
            public_inputs,
            zerocheck_powers,
            sum: F::zero(),
        }
    }

    pub(crate) fn fold(self, other: Self, folder: FieldFolder<F>, sum: F) -> Self {
        let witness_commit = folder.fold_abstract(self.witness_commit, other.witness_commit);
        let mut public_inputs = [F::zero(); I];
        for (i, input) in public_inputs.iter_mut().enumerate() {
            *input = folder.fold_elem(self.public_inputs[i], other.public_inputs[i]);
        }
        let zerocheck_powers = folder.fold_powers(self.zerocheck_powers, other.zerocheck_powers);

        Self {
            witness_commit,
            public_inputs,
            zerocheck_powers,
            sum,
        }
    }
}

impl<F, C, const I: usize> Message<F> for FoldableLcsInstance<F, C, I>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        C::Commitment::len(vars, param_resolver) + I + CompactPowers::<F>::len(vars, param_resolver)
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = self.witness_commit.to_field_elements();
        elems.extend(self.public_inputs);
        elems.extend(self.zerocheck_powers.to_field_elements());
        elems
    }
}
