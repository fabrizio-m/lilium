//! Some common instances

use ark_ff::Field;

/// Claim to some implicit polynomial evaluating to the given value
/// at the given point.
pub struct PolyEvalCheck<F: Field> {
    pub vars: Vec<F>,
    pub eval: F,
}
