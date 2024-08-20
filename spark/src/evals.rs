use crate::mvlookup::{LookupEval, LookupIdx};
use ark_ff::Field;
use std::ops::Index;
use sumcheck::{
    polynomials::Evals,
    utils::{ZeroAvailable, ZeroCheckAvailable},
};

/// one of the evaluations nm variate sparse polynomial
/// with at most 2^m non-zero evaluations.
/// A common example would D = 2 for a sparse matrix
pub struct SparkEval<F: Field, const D: usize> {
    dimensions: [DimensionEval<F>; D],
    /// 0..n
    normal_index: F,
    val: F,
    zero_eq: F,
    /// 0
    zero: F,
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
    /// the lookups into eq_eval constrained by this dimension's
    /// index
    eq_lookups: F,
}

#[derive(Clone, Copy, Debug)]
pub enum DimensionIndex {
    Lookup(LookupIdx),
    EqEval,
    Dimension,
    EqLookup,
}

impl<F: Field> Index<DimensionIndex> for DimensionEval<F> {
    type Output = F;

    fn index(&self, index: DimensionIndex) -> &Self::Output {
        match index {
            DimensionIndex::Lookup(lookup_idx) => &self.lookup[lookup_idx],
            DimensionIndex::EqEval => &self.eq_eval,
            DimensionIndex::Dimension => &self.dimension_index,
            DimensionIndex::EqLookup => &self.eq_lookups,
        }
    }
}

impl<F: Field> Evals<F> for DimensionEval<F> {
    type Idx = DimensionIndex;

    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
        let lookup = self.lookup.combine(&other.lookup, &f);
        let eq_eval = f(self.eq_eval, other.eq_eval);
        let dimension_index = f(self.dimension_index, other.dimension_index);
        let eq_lookups = f(self.eq_lookups, other.eq_lookups);
        Self {
            lookup,
            eq_eval,
            dimension_index,
            eq_lookups,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum SparkIndex {
    Dimension(usize, DimensionIndex),
    NormalIndex,
    ZeroEq,
    Val,
    Zero,
}
impl ZeroCheckAvailable for SparkIndex {
    fn zerocheck_eq() -> Self {
        Self::ZeroEq
    }
}
impl ZeroAvailable for SparkIndex {
    fn zero() -> Self {
        Self::Zero
    }
}

impl<F: Field, const D: usize> Index<SparkIndex> for SparkEval<F, D> {
    type Output = F;

    fn index(&self, index: SparkIndex) -> &Self::Output {
        match index {
            SparkIndex::Dimension(i, dim) => &self.dimensions[i][dim],
            SparkIndex::NormalIndex => &self.normal_index,
            SparkIndex::Val => &self.val,
            SparkIndex::ZeroEq => &self.zero_eq,
            SparkIndex::Zero => &self.zero,
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
        let zero_eq = f(self.zero_eq, other.zero_eq);
        // F::zero() should give the same result
        let zero = f(self.zero, other.zero);
        Self {
            dimensions,
            normal_index,
            val,
            zero_eq,
            zero,
        }
    }
}
