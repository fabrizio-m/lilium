//! Multivariate polynomial computation and optimal evaluation
//! Intended for for multivariate polynomials where the variables are
//! univariate polynomials

pub mod compute;
pub mod evaluate;
pub mod expression;
pub mod message_eval;
#[cfg(test)]
mod test;
