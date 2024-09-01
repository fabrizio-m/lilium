use crate::{
    challenges::{CompressionChallenge, LookupChallenge, SparkChallenges},
    mvlookup::{LookupEval, LookupIdx},
    structure::{DimensionStructure, SparkStructure},
};
use ark_ff::Field;
use std::ops::Index;
use sumcheck::{
    eq,
    polynomials::{Evals, MultiPoint},
    utils::{ZeroAvailable, ZeroCheckAvailable},
};

/// one of the evaluations nm variate sparse polynomial
/// with at most 2^m non-zero evaluations.
/// A common example would D = 2 for a sparse matrix
#[derive(Clone, Debug)]
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
pub struct DimensionEval<F: Field> {
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
impl<F: Field> DimensionEval<F> {
    fn evals(
        point: MultiPoint<F>,
        structure: &DimensionStructure<F>,
        normal_index: &[F],

        challenges: &SparkChallenges<F>,
    ) -> Vec<Self> {
        let eq_eval = eq::eq(point);
        let eq_lookups: Vec<F> = structure.lookups.iter().map(|i| eq_eval[*i]).collect();
        // let lookups = structure.dimen
        let compression_chall = *challenges.compression_challenge();
        let table: Vec<F> = eq_eval
            .iter()
            .zip(normal_index.iter())
            .map(|(eq, idx)| *idx + compression_chall * eq)
            .collect();
        let lookups = structure.lookups(&table);

        let lookup_challenge = challenges.lookup_challenge();
        let lookup =
            LookupEval::evals(&lookups, &table, &structure.counts_field, *lookup_challenge);

        let evals: Vec<Self> = eq_eval
            .into_iter()
            .zip(eq_lookups)
            .zip(lookup)
            .zip(&structure.lookups_field)
            .map(|x| {
                let x = x;
                let (((eq_eval, eq_lookups), lookup), dimension_index) = x;
                Self {
                    lookup,
                    eq_eval,
                    dimension_index: *dimension_index,
                    eq_lookups,
                }
            })
            .collect();
        evals
    }
}

impl<F: Field, const D: usize> SparkEval<F, D> {
    pub fn evals(
        structure: &SparkStructure<F, D>,
        points: [MultiPoint<F>; D],
        challenges: SparkChallenges<F>,
        zero_check_point: MultiPoint<F>,
    ) -> Vec<Self> {
        let mut points = points.into_iter();
        let dimensions = structure.dimensions.each_ref().map(|struc| {
            let normal_index = &structure.normal_index;
            let point = points.next().unwrap();
            let evals = DimensionEval::evals(point, struc, &normal_index, &challenges);
            evals
        });

        let zero_eq = eq::eq(zero_check_point);

        let mut d = dimensions.map(|x| x.into_iter());

        let evals = structure
            .normal_index
            .iter()
            .zip(&structure.val)
            .zip(zero_eq.into_iter())
            .map(|x| {
                let ((normal_index, val), zero_eq) = x;
                let dimensions = (&mut d).each_mut().map(|x| x.next().unwrap());
                SparkEval {
                    normal_index: *normal_index,
                    val: *val,
                    zero_eq,
                    zero: F::zero(),
                    dimensions,
                }
            })
            .collect();

        evals
    }
}
