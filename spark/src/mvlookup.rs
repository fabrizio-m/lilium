use ark_ff::Field;
use std::ops::Index;
use sumcheck::{
    polynomials::Evals,
    sumcheck::Var,
    utils::{ZeroCheck, ZeroSumcheck},
};

#[derive(Clone, Copy)]
enum ShapeIdx {
    Frac,
    Num,
    Den,
}
struct ShapeEval<F: Field> {
    numerator: F,
    denominator: F,
}

impl<F: Field> Index<ShapeIdx> for ShapeEval<F> {
    type Output = F;

    fn index(&self, index: ShapeIdx) -> &Self::Output {
        match index {
            ShapeIdx::Num => &self.numerator,
            ShapeIdx::Den => &self.denominator,
            _ => todo!(),
        }
    }
}
impl<F: Field> Evals<F> for ShapeEval<F> {
    type Idx = ShapeIdx;

    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
        let numerator = f(self.numerator, other.numerator);
        let denominator = f(self.denominator, other.denominator);
        ShapeEval {
            numerator,
            denominator,
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

pub fn lookup<F, V>(
    lookups: V,
    table: V,
    counts: V,
    fracs: (V, V),
    chall: F,
) -> ([ZeroCheck<V>; 2], ZeroSumcheck<V>)
where
    F: Field,
    V: Var<F>,
{
    let (frac1, frac2) = fracs;
    // let left = shape_dynamic_count(set, counts, frac1, chall);
    let left = shape_fixed_count(lookups, frac1, chall);
    let right = shape_dynamic_count(table, counts, frac2, chall);
    let equality = left.clone() - right.clone();
    let zero_checks = [left, right].map(ZeroCheck);
    (zero_checks, ZeroSumcheck(equality))
}
