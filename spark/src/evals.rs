use crate::mvlookup::{LookupEval, LookupIdx};
use ark_ff::Field;
use std::ops::Index;
use sumcheck::polynomials::Evals;

/// one of the evaluations nm variate sparse polynomial
/// with at most 2^m non-zero evaluations.
/// A common example would D = 2 for a sparse matrix
pub struct SparkEval<F: Field, const D: usize> {
    dimensions: [DimensionEval<F>; D],
    /// 0..n
    normal_index: F,
    val: F,
}
/// Evals corresponding to a particular dimension
#[derive(Clone, Copy, Debug)]
struct DimensionEval<F: Field> {
    lookup: LookupEval<F>,
    /// eq(x,r) for the r corresponding to this dimension
    eq_eval: F,
    /// the indices of this particular dimension, a multiset
    /// made of elements from the normal index
    dimension_index: F,
}

#[derive(Clone, Copy, Debug)]
pub enum DimensionIndex {
    Lookup(LookupIdx),
    EqEval,
    Dimension,
}

impl<F: Field> Index<DimensionIndex> for DimensionEval<F> {
    type Output = F;

    fn index(&self, index: DimensionIndex) -> &Self::Output {
        match index {
            DimensionIndex::Lookup(lookup_idx) => &self.lookup[lookup_idx],
            DimensionIndex::EqEval => &self.eq_eval,
            DimensionIndex::Dimension => &self.dimension_index,
        }
    }
}

impl<F: Field> Evals<F> for DimensionEval<F> {
    type Idx = DimensionIndex;

    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
        let lookup = self.lookup.combine(&other.lookup, &f);
        let eq_eval = f(self.eq_eval, other.eq_eval);
        let dimension_index = f(self.dimension_index, other.dimension_index);
        Self {
            lookup,
            eq_eval,
            dimension_index,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum SparkIndex {
    Dimension(usize, DimensionIndex),
    NormalIndex,
    Val,
}

impl<F: Field, const D: usize> Index<SparkIndex> for SparkEval<F, D> {
    type Output = F;

    fn index(&self, index: SparkIndex) -> &Self::Output {
        match index {
            SparkIndex::Dimension(i, dim) => &self.dimensions[i][dim],
            SparkIndex::NormalIndex => &self.normal_index,
            SparkIndex::Val => &self.val,
        }
    }
}
impl<F: Field, const D: usize> Evals<F> for SparkEval<F, D> {
    type Idx = SparkIndex;

    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
        let mut dimensions = self.dimensions.clone();
        for i in 0..D {
            let dim = dimensions[i];
            let comb = dim.combine(&other.dimensions[i], &f);
            dimensions[i] = comb;
        }
        let normal_index = f(self.normal_index, other.normal_index);
        let val = f(self.val, other.val);
        Self {
            dimensions,
            normal_index,
            val,
        }
    }
}
/*
struct SparkFunction<const D: usize>;
impl<F: Field, const D: usize> SumcheckFunction<F> for SparkFunction<D> {
    type Idx = EvalIndex;

    type Mles = SparkEval<F, D>;

    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E) -> V {
        let val = env.get(EvalIndex::Val);
        let mut product = val;
        for i in 0..D {
            let dim = env.get(EvalIndex::Dimension(i));
            product = dim * product;
        }
        product
    }
}
*/
