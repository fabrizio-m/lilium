use ark_ff::Field;
use sumcheck::{eq::eq_subset, polynomials::MultiPoint};

pub mod flcs;
pub mod lcs;
mod linearized;
pub mod matrix_eval;

fn eval_input_selector<F: Field>(point: &MultiPoint<F>, input_len: usize) -> F {
    let log_input = input_len.next_power_of_two().ilog2().max(1);
    let eq_evals = eq_subset(point, log_input as usize);
    // Given that we multiply by either 1 or 0, we can just add the 1s and
    // ignore the zeros.
    eq_evals
        .into_iter()
        .take(input_len)
        .fold(F::zero(), |acc, e| acc + e)
}

fn eval_inputs<F: Field>(vars: &[F], inputs: &[F]) -> F {
    let log_input = inputs.len().next_power_of_two().ilog2().max(1);
    let eq_evals = eq_subset(&vars.into(), log_input as usize);
    inputs
        .iter()
        .zip(eq_evals)
        .fold(F::zero(), |acc, (e, eq)| acc + eq * e)
}
