use crate::sumcheck::Var;
use ark_ff::Field;

/// Should check sumcheck were the sum is zero
pub struct ZeroSumcheck<V>(pub V);
/// Should check that the polynomial evaluates to 0 over the domain
pub struct ZeroCheck<V>(pub V);

/// Converts zero check into sumcheck, where zeq is used to
/// basically evaluate the polynomial in a random point
pub fn zero_check_to_sumcheck<F, V>(zero_check: ZeroCheck<V>, zeq: &V) -> ZeroSumcheck<V>
where
    F: Field,
    V: Var<F>,
{
    ZeroSumcheck(zero_check.0 * zeq)
}
