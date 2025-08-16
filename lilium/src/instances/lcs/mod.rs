use ark_ff::Field;
use commit::CommmitmentScheme;
use std::marker::PhantomData;
use transcript::Message;

mod key;
mod reduction;
mod sumcheck_argument;
mod verifying;

pub struct LcsInstance<F: Field, C: CommmitmentScheme<F>, const I: usize> {
    witness_commit: C::Commitment,
    public_inputs: [F; I],
}

impl<F: Field, C: CommmitmentScheme<F>, const I: usize> Message<F> for LcsInstance<F, C, I> {
    fn len(vars: usize, param_resolver: &transcript::params::ParamResolver) -> usize {
        C::Commitment::len(vars, param_resolver) + I
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = self.witness_commit.to_field_elements();
        elems.extend(self.public_inputs);
        elems
    }
}

pub struct LcsProver<C, const I: usize, const IO: usize>(PhantomData<C>);
