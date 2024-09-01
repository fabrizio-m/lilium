//! A linear sumcheck prover

pub(crate) mod barycentric_eval;
pub(crate) mod degree;
pub mod eq;
pub mod eval_check;
pub(crate) mod message;
pub mod polynomials;
pub mod sumcheck;
#[cfg(test)]
mod tests;
pub mod utils;

#[derive(Debug, Clone, Copy)]
pub enum SumcheckError {
    /// A message had an incorrect degree
    MessageDegree,
    /// The sum of both halves defers from the claimed sum
    RoundSum,
}
