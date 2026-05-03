use ark_ff::{batch_inversion, Field};
use std::vec::IntoIter;
use sumcheck::{
    eq,
    polynomials::{Evals, MultiPoint},
    sumcheck::{CommitType, EvalKind},
};

use crate::spark2::SparkSparseMle;

#[derive(Clone, Copy, Debug)]
struct DimensionOpen<V> {
    address_segment: V,
    eq_lookup: V,
    inverse: V,
}

impl<V> DimensionOpen<V> {
    pub fn map<V2, F: Fn(V) -> V2>(self, f: F) -> DimensionOpen<V2> {
        let Self {
            address_segment,
            eq_lookup,
            inverse,
        } = self;
        DimensionOpen {
            address_segment: f(address_segment),
            eq_lookup: f(eq_lookup),
            inverse: f(inverse),
        }
    }

    fn new(address_segment: V, eq_lookup: V, inverse: V) -> Self {
        Self {
            address_segment,
            eq_lookup,
            inverse,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SparkOpen<V, const N: usize> {
    dimensions: [DimensionOpen<V>; N],
    value: V,
    zerocheck: V,
}

impl<V, const N: usize> SparkOpen<V, N> {
    pub fn map<V2, F: Fn(V) -> V2>(self, f: F) -> SparkOpen<V2, N> {
        let Self {
            dimensions,
            value,
            zerocheck,
        } = self;

        let dimensions = dimensions.map(|dim| dim.map(&f));
        SparkOpen {
            dimensions,
            value: f(value),
            zerocheck: f(zerocheck),
        }
    }

    pub fn small_evals(zerocheck: V) -> SparkOpen<Option<V>, N> {
        let dimensions = [(); N].map(|_| DimensionOpen::new(None, None, None));
        SparkOpen {
            dimensions,
            value: None,
            zerocheck: Some(zerocheck),
        }
    }
}

impl<F: Field, const N: usize> SparkOpen<F, N> {
    pub fn evals(
        structure: &[Self],
        sparse_mle: &SparkSparseMle<F, N>,
        points: [MultiPoint<F>; N],
        zero_check_point: &MultiPoint<F>,
        lookup_challenge: F,
        compression_challenge: F,
    ) -> Vec<Self> {
        let mut mles = structure.to_vec();
        let zerocheck_evals = eq::eq(zero_check_point);

        for (evals, zerocheck_eval) in mles.iter_mut().zip(zerocheck_evals) {
            evals.zerocheck = zerocheck_eval;
        }

        for (i, point) in points.iter().enumerate() {
            let eq_evals = eq::eq(point);
            let indexed_table: Vec<F> = eq_evals
                .iter()
                .enumerate()
                .map(|(i, eq)| F::from(i as u8) * compression_challenge + eq + lookup_challenge)
                .collect();
            let mut inverses = indexed_table.clone();
            batch_inversion(&mut inverses);

            for (evals, address) in mles.iter_mut().zip(&sparse_mle.addresses) {
                let address_segment = address[i];
                let lookup = eq_evals[address_segment as usize];
                let inverse = inverses[address_segment as usize];
                evals.dimensions[i].eq_lookup = lookup;
                evals.dimensions[i].inverse = inverse;
            }
        }

        mles
    }

    pub fn new_structure(value: F, addresses: [u8; N]) -> Self {
        let dimensions = addresses.map(|addr| {
            let address_segment = F::from(addr);
            DimensionOpen {
                address_segment,
                eq_lookup: F::zero(),
                inverse: F::zero(),
            }
        });
        Self {
            dimensions,
            value,
            zerocheck: F::zero(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum DimensionIndex {
    Address,
    EqLookup,
    Inverse,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum SparkIndex {
    Dimension(DimensionIndex, usize),
    Value,
    Zerocheck,
}

impl<V: Copy + Sync + Send> Evals<V> for DimensionOpen<V> {
    type Idx = DimensionIndex;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            DimensionIndex::Address => &self.address_segment,
            DimensionIndex::EqLookup => &self.eq_lookup,
            DimensionIndex::Inverse => &self.inverse,
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let address_segment = f(self.address_segment, other.address_segment);
        let eq_lookup = f(self.eq_lookup, other.eq_lookup);
        let inverse = f(self.inverse, other.inverse);
        Self {
            address_segment,
            eq_lookup,
            inverse,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self {
            address_segment,
            eq_lookup,
            inverse,
        } = self;
        vec.extend([address_segment, eq_lookup, inverse]);
    }

    fn unflatten(elems: &mut IntoIter<V>) -> Self {
        let address_segment = elems.next().unwrap();
        let eq_lookup = elems.next().unwrap();
        let inverse = elems.next().unwrap();
        Self {
            address_segment,
            eq_lookup,
            inverse,
        }
    }
}

impl<V: Copy + Sync + Send, const N: usize> Evals<V> for SparkOpen<V, N> {
    type Idx = SparkIndex;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            SparkIndex::Dimension(dimension_index, i) => {
                let dimension = &self.dimensions[i];
                dimension.index(dimension_index)
            }
            SparkIndex::Value => &self.value,
            SparkIndex::Zerocheck => &self.zerocheck,
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let dimensions = self.dimensions.combine(&other.dimensions, &f);
        let value = f(self.value, other.value);
        let zerocheck = f(self.zerocheck, other.zerocheck);
        Self {
            dimensions,
            value,
            zerocheck,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self {
            dimensions,
            value,
            zerocheck,
        } = self;
        dimensions.flatten(vec);
        vec.push(value);
        vec.push(zerocheck);
    }

    fn unflatten(elems: &mut IntoIter<V>) -> Self {
        let dimensions = <[DimensionOpen<V>; N]>::unflatten(elems);
        let value = elems.next().unwrap();
        let zerocheck = elems.next().unwrap();
        Self {
            dimensions,
            value,
            zerocheck,
        }
    }
}

pub const fn kinds<const N: usize>() -> SparkOpen<EvalKind, N> {
    let dimensions = [DimensionOpen {
        address_segment: EvalKind::Committed(CommitType::Structure),
        eq_lookup: EvalKind::Committed(CommitType::Instance),
        inverse: EvalKind::Committed(CommitType::Instance),
    }; N];
    SparkOpen {
        dimensions,
        value: EvalKind::Committed(CommitType::Structure),
        zerocheck: EvalKind::FixedSmall,
    }
}
