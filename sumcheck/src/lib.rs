//! A linear sumcheck prover

pub(crate) mod barycentric_eval;
pub(crate) mod degree;
pub mod eval_check;
pub(crate) mod message;
pub mod polynomials;
pub mod sumcheck;

#[derive(Debug, Clone, Copy)]
pub enum SumcheckError {
    /// A message had an incorrect degree
    MessageDegree,
    /// The sum of both halves defers from the claimed sum
    RoundSum,
}
