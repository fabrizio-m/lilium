use ark_ff::Field;
use commit::CommmitmentScheme;

mod linearized;
pub mod matrix_eval;

struct Instance<F: Field, C: CommmitmentScheme<F>, const I: usize> {
    witness_commit: C::Commitment,
    public_inputs: [F; I],
}
