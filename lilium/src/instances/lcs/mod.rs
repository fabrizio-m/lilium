use ark_ff::Field;
use commit::CommmitmentScheme;
use std::marker::PhantomData;
use transcript::Message;

mod key;
mod proving;
mod reduction;
mod reduction_proving;
pub(crate) mod sumcheck_argument;
pub mod verifying;

pub(crate) use sumcheck_argument::LcsSumcheck;

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
