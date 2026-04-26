use crate::{
    challenges::{CompressionChallenge, LookupChallenge, SparkChallenges},
    mvlookup::{LookupEval, LookupIdx},
    structure::{DimensionStructure, SparkStructure},
};
use ark_ff::Field;
use sumcheck::{
    eq,
    polynomials::{Evals, MultiPoint},
    sumcheck::{CommitType, EvalKind},
    utils::{ZeroAvailable, ZeroCheckAvailable},
};

/// one of the evaluations nm variate sparse polynomial
/// with at most 2^m non-zero evaluations.
/// A common example would D = 2 for a sparse matrix
#[derive(Clone, Debug)]
pub struct SparkEval<V, const D: usize> {
    dimensions: [DimensionEval<V>; D],
    /// 0..n
    normal_index: V,
    val: V,
    zero_eq: V,
    /// 0
    zero: V,
}

/// Evals corresponding to a particular dimension
#[derive(Clone, Copy, Debug)]
pub struct DimensionEval<V> {
    lookup: LookupEval<V>,
    /// eq(x,r) for the r corresponding to this dimension
    eq_eval: V,
    /// the indices of this particular dimension, a multiset
    /// made of elements from the normal index
    dimension_index: V,
    /// the lookups into eq_eval constrained by this dimension's
    /// index
    eq_lookups: V,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DimensionIndex {
    Lookup(LookupIdx),
    EqEval,
    Dimension,
    EqLookup,
}

impl<V: Copy> Evals<V> for DimensionEval<V> {
    type Idx = DimensionIndex;

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
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

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            DimensionIndex::Lookup(lookup_idx) => self.lookup.index(lookup_idx),
            DimensionIndex::EqEval => &self.eq_eval,
            DimensionIndex::Dimension => &self.dimension_index,
            DimensionIndex::EqLookup => &self.eq_lookups,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self {
            lookup,
            eq_eval,
            dimension_index,
            eq_lookups,
        } = self;
        lookup.flatten(vec);
        vec.push(eq_eval);
        vec.push(dimension_index);
        vec.push(eq_lookups);
    }

    fn unflatten(elems: &mut std::vec::IntoIter<V>) -> Self {
        let lookup = LookupEval::unflatten(elems);
        let eq_eval = elems.next().unwrap();
        let dimension_index = elems.next().unwrap();
        let eq_lookups = elems.next().unwrap();
        Self {
            lookup,
            eq_eval,
            dimension_index,
            eq_lookups,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

impl<V: Copy, const D: usize> Evals<V> for SparkEval<V, D> {
    type Idx = SparkIndex;

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let mut dimensions = self.dimensions;
        for (i, dim) in dimensions.iter_mut().enumerate() {
            let comb = dim.combine(&other.dimensions[i], &f);
            *dim = comb;
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

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            SparkIndex::Dimension(i, dim) => self.dimensions[i].index(dim),
            SparkIndex::NormalIndex => &self.normal_index,
            SparkIndex::Val => &self.val,
            SparkIndex::ZeroEq => &self.zero_eq,
            SparkIndex::Zero => &self.zero,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self {
            dimensions,
            normal_index,
            val,
            zero_eq,
            zero,
        } = self;
        dimensions.flatten(vec);
        vec.extend([normal_index, val, zero_eq, zero]);
    }

    fn unflatten(elems: &mut std::vec::IntoIter<V>) -> Self {
        let dimensions = <[DimensionEval<V>; D] as Evals<V>>::unflatten(elems);
        let normal_index = elems.next().unwrap();
        let val = elems.next().unwrap();
        let zero_eq = elems.next().unwrap();
        let zero = elems.next().unwrap();
        Self {
            dimensions,
            normal_index,
            val,
            zero_eq,
            zero,
        }
    }
}
impl<V> DimensionEval<V> {
    pub const fn kind() -> DimensionEval<EvalKind> {
        DimensionEval {
            lookup: LookupEval::<()>::kind(true),
            eq_eval: EvalKind::FixedSmall,
            dimension_index: EvalKind::Committed(CommitType::Structure),
            eq_lookups: EvalKind::Committed(CommitType::Instance),
        }
    }
    /// compute the small evals
    pub fn small_evals<F: Field>(eq_eval: F) -> DimensionEval<Option<F>> {
        DimensionEval {
            lookup: LookupEval::default(),
            eq_eval: Some(eq_eval),
            dimension_index: None,
            eq_lookups: None,
        }
    }

    fn map<B, M>(self, f: M) -> DimensionEval<B>
    where
        B: Copy + std::fmt::Debug,
        M: Fn(V) -> B,
    {
        let DimensionEval {
            lookup,
            eq_eval,
            dimension_index,
            eq_lookups,
        } = self;
        let lookup = lookup.map(&f);
        DimensionEval {
            lookup,
            eq_eval: f(eq_eval),
            dimension_index: f(dimension_index),
            eq_lookups: f(eq_lookups),
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
        let eq_eval = eq::eq(&point);
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

impl<V, const D: usize> SparkEval<V, D> {
    pub const fn kinds() -> SparkEval<EvalKind, D> {
        let dimensions = [DimensionEval::<()>::kind(); D];
        SparkEval {
            dimensions,
            //TODO: maybe it can be made small
            normal_index: EvalKind::Committed(CommitType::Structure),
            val: EvalKind::Committed(CommitType::Structure),
            zero_eq: EvalKind::FixedSmall,
            zero: EvalKind::FixedSmall,
        }
    }
    /// compute the small evals
    pub fn small_evals<F: Field>(zero_eq_eval: F, eq_evals: [F; D]) -> SparkEval<Option<F>, D> {
        let dimensions = eq_evals.map(DimensionEval::<V>::small_evals);
        SparkEval {
            dimensions,
            normal_index: None,
            val: None,
            zero_eq: Some(zero_eq_eval),
            zero: Some(F::zero()),
        }
    }

    pub fn map<B, M>(self, f: M) -> SparkEval<B, D>
    where
        B: Copy + std::fmt::Debug,
        M: Fn(V) -> B,
    {
        let Self {
            dimensions,
            normal_index,
            val,
            zero_eq,
            zero,
        } = self;
        let dimensions = dimensions.map(|x| x.map(&f));
        SparkEval {
            dimensions,
            normal_index: f(normal_index),
            val: f(val),
            zero_eq: f(zero_eq),
            zero: f(zero),
        }
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
            DimensionEval::evals(point, struc, normal_index, &challenges)
        });

        let zero_eq = eq::eq(&zero_check_point);

        let mut d = dimensions.map(|x| x.into_iter());

        let evals = structure
            .normal_index
            .iter()
            .zip(&structure.val)
            .zip(zero_eq)
            .map(|x| {
                let ((normal_index, val), zero_eq) = x;
                let dimensions = d.each_mut().map(|x| x.next().unwrap());
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
