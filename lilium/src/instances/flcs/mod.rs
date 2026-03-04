use ark_ff::Field;
use commit::CommmitmentScheme;
use sumcheck::zerocheck::CompactPowers;
use transcript::{params::ParamResolver, Message};

#[derive(Clone, Debug)]
pub struct FoldableLcsInstance<F, C, const I: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    witness_commit: C::Commitment,
    public_inputs: [F; I],
    zerocheck_powers: CompactPowers<F>,
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
