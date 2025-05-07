use ark_ff::Field;
use commit::CommmitmentScheme;
use sumcheck::polynomials::MultiPoint;
use transcript::{params::ParamResolver, Message};

pub mod proving;
pub mod sumcheck_argument;

/// A linearized committed ccs instance
pub struct LinearizedInstance<F: Field, C: CommmitmentScheme<F>, const I: usize, const IO: usize> {
    /// C = commit(w) such that z = (u,x,w), with x = public_inputs
    pub witness_commit: C::Commitment,
    /// first element of the vector to be multiplied with the matrices, formed
    /// by this, the public inputs and the witness. It's 1 in trivial cases.
    pub u: F,
    /// x
    pub public_inputs: [F; I],
    /// random point eq(rx,y) to indirectly eval the matrices.
    pub rx: MultiPoint<F>,
    /// the sum of the resulting vector from each matrix multiplication
    pub products: [F; IO],
}

impl<F, C, const I: usize, const IO: usize> Message<F> for LinearizedInstance<F, C, I, IO>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        let commit = C::Commitment::len(vars, param_resolver);
        commit + 1 + I + vars + IO
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = self.witness_commit.to_field_elements();
        elems.push(self.u);
        elems.extend_from_slice(&self.public_inputs);
        elems.extend_from_slice(&self.rx.to_field_elements());
        elems.extend_from_slice(&self.products);
        elems
    }
}
