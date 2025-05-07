use ark_ff::Field;
use sumcheck::{eq::eq_subset, polynomials::MultiPoint};

pub mod lcs;
mod linearized;
pub mod matrix_eval;

fn eval_input_selector<F: Field>(point: &MultiPoint<F>, input_len: usize) -> F {
    let eq_evals = eq_subset(&point, input_len + 1);
    // Given that we multiply by either 1 or 0, we can just add the 1s and
    // ignore the zeros.
    eq_evals
        .into_iter()
        .take(input_len + 1)
        .fold(F::zero(), |acc, e| acc + e)
}

fn eval_ux<F: Field>(vars: &[F], u: F, inputs: &[F]) -> F {
    let eq_evals = eq_subset(&vars.into(), inputs.len() + 1);
    let evals = [u];
    let evals = evals.iter().chain(inputs);
    evals
        .zip(eq_evals)
        .fold(F::zero(), |acc, (e, eq)| acc + eq * e)
}
