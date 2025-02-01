use ark_ff::Field;
use commit::CommmitmentScheme;
use sumcheck::polynomials::MultiPoint;
use transcript::Message;

pub mod matrix_eval;
struct Instance<F: Field, C: CommmitmentScheme<F>, const I: usize> {
    witness_commit: C::Commitment,
    public_inputs: [F; I],
}
pub(crate) struct LinearizedInstance<
    F: Field,
    C: CommmitmentScheme<F>,
    const I: usize,
    const IO: usize,
> {
    witness_commit: C::Commitment,
    /// first element of the vector to be multiplied with the matrices, formed
    /// by this, the public inputs and the witness. It's 1 in trivial cases.
    u: F,
    public_inputs: [F; I],
    /// the sum of the resulting vector from each matrix multiplication
    matrix_evals: [F; IO],
}
