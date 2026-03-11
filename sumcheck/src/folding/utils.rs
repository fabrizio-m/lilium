use std::ops::{Add, Mul};

use crate::{polynomials::Evals, zerocheck::CompactPowers};
use ark_ff::Field;

// Type with methods to facilitate 2->1 folding of different
// types found in instances or witnesses.
#[derive(Clone, Copy, Debug)]
pub struct FieldFolder<F> {
    r: F,
    // 1 - r
    nr: F,
}

impl<F: Field> FieldFolder<F> {
    pub fn new(r: F) -> Self {
        let nr = F::one() - r;
        Self { r, nr }
    }

    pub fn fold_elem(&self, a: F, b: F) -> F {
        a * self.nr + b * self.r
    }

    pub fn fold_powers(&self, a: CompactPowers<F>, b: CompactPowers<F>) -> CompactPowers<F> {
        a * self.nr + b * self.r
    }

    pub fn fold_mles<E: Evals<F>>(&self, a: &mut [E], b: &[E]) {
        for (a, b) in a.iter_mut().zip(b) {
            let folded = a.combine(b, |a, b| self.fold_elem(a, b));
            *a = folded;
        }
    }

    /// Folds any type which can be multiplied by field elements and added to itself.
    /// Useful for folding commitments.
    pub fn fold_abstract<T>(&self, a: T, b: T) -> T
    where
        T: Mul<F, Output = T> + Add<Output = T>,
    {
        a * self.nr + b * self.r
    }
}
