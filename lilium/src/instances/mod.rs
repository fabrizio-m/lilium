use ark_ff::Field;
use commit::CommmitmentScheme2;

mod linearized;
pub mod matrix_eval;

struct Instance<F: Field, C: CommmitmentScheme2<F>, const I: usize> {
    witness_commit: C::Commitment,
    public_inputs: [F; I],
}
