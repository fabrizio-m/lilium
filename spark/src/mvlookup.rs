use ark_ff::Field;
use std::ops::Index;
use sumcheck::{
    polynomials::Evals,
    sumcheck::Var,
    utils::{ZeroCheck, ZeroSumcheck},
};

use crate::challenges::LookupChallenge;

#[derive(Clone, Copy, Debug)]
pub enum LookupIdx {
    /// Claimed fraction for left side
    Frac1,
    /// Claimed fraction for right side
    Frac2,
    /// Counts of how many times a table element appears in the lookups
    Counts,
}
#[derive(Clone, Copy, Debug)]
pub struct LookupEval<F: Field> {
    frac1: F,
    frac2: F,
    counts: F,
}

impl<F: Field> Index<LookupIdx> for LookupEval<F> {
    type Output = F;

    fn index(&self, index: LookupIdx) -> &Self::Output {
        match index {
            LookupIdx::Frac1 => &self.frac1,
            LookupIdx::Frac2 => &self.frac2,
            LookupIdx::Counts => &self.counts,
        }
    }
}
impl<F: Field> Evals<F> for LookupEval<F> {
    type Idx = LookupIdx;

    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
        let frac1 = f(self.frac1, other.frac1);
        let frac2 = f(self.frac2, other.frac2);
        let counts = f(self.counts, other.counts);
        LookupEval {
            frac1,
            frac2,
            counts,
        }
    }
}

fn shape_dynamic_count<F: Field, V: Var<F>>(set: V, counts: V, frac: V, chall: F) -> V {
    frac * (set + chall) - counts
}

fn shape_fixed_count<F: Field, V: Var<F>>(set: V, frac: V, chall: F) -> V {
    frac * (set + chall) - F::one()
}

/// Multiset equality check between 2 multisets
pub fn multiset_check<F, V>(
    multisets: (V, V),
    fracs: (V, V),
    chall: F,
) -> ([ZeroCheck<V>; 2], ZeroSumcheck<V>)
where
    F: Field,
    V: Var<F>,
{
    let (set1, set2) = multisets;
    let (frac1, frac2) = fracs;
    let left_check = shape_fixed_count(set1, frac1.clone(), chall);
    let right_check = shape_fixed_count(set2, frac2.clone(), chall);
    let equality = frac1 - frac2;
    (
        [ZeroCheck(left_check), ZeroCheck(right_check)],
        ZeroSumcheck(equality),
    )
}

/// Lookups where [counts] states how many times each element in the table
/// appears in the lookups
pub fn lookup<F, V, C>(
    lookups: V,
    table: V,
    counts: V,
    fracs: (V, V),
    challenges: &C,
) -> ([ZeroCheck<V>; 2], ZeroSumcheck<V>)
where
    F: Field,
    V: Var<F>,
    C: LookupChallenge<F>,
{
    let (frac1, frac2) = fracs;
    let chall = challenges.lookup_challenge();
    let left = shape_fixed_count(lookups, frac1, *chall);
    let right = shape_dynamic_count(table, counts, frac2, *chall);
    let equality = left.clone() - right.clone();
    let zero_checks = [left, right].map(ZeroCheck);
    (zero_checks, ZeroSumcheck(equality))
}

impl<F: Field> LookupEval<F> {
    pub fn evals(lookups: &[F], table: &[F], counts: &[F], challenge: F) -> Vec<Self> {
        assert_eq!(lookups.len(), table.len());
        assert_eq!(lookups.len(), counts.len());
        let mut left_den: Vec<F> = lookups.iter().map(|x| *x + challenge).collect();
        ark_ff::fields::batch_inversion(&mut left_den);
        let frac1 = left_den;
        let mut right_den: Vec<F> = table.iter().map(|x| *x + challenge).collect();
        ark_ff::fields::batch_inversion(&mut right_den);

        counts
            .iter()
            .zip(frac1)
            .zip(right_den)
            .map(|x| {
                let ((counts, frac1), right_den) = x;
                let frac2 = right_den * counts;
                LookupEval {
                    frac1,
                    counts: *counts,
                    frac2,
                }
            })
            .collect()
    }
}
