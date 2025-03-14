//! definitions for static commitments

use ark_ff::Field;
use std::iter::successors;

#[derive(Debug)]
pub struct DimensionStructure<F: Field> {
    /// where the value is how many times the element in such index appears
    /// in lookups
    pub _counts: Vec<usize>,
    /// where the value is the index of the table where the lookup in this index
    /// comes from
    pub lookups: Vec<usize>,
    /// same as counts, but as field elements to save time
    pub counts_field: Vec<F>,
    /// same as lookups, but as field elements to save time
    pub lookups_field: Vec<F>,
}

pub struct SparkStructure<F: Field, const D: usize> {
    pub dimensions: [DimensionStructure<F>; D],
    // TODO: should be in a more global as it isn't unique to any
    // commitment
    /// 0..n
    pub normal_index: Vec<F>,
    /// the evaluations over the domain
    pub val: Vec<F>,
}

pub type SparkMatrix<F> = SparkStructure<F, 2>;

impl<F: Field> DimensionStructure<F> {
    pub fn new(counts: Vec<usize>, lookups: Vec<usize>) -> Self {
        let counts_field = counts.iter().map(|x| *x as u64).map(F::from).collect();
        let lookups_field = lookups.iter().map(|x| *x as u64).map(F::from).collect();
        let _counts = counts;
        Self {
            _counts,
            lookups,
            counts_field,
            lookups_field,
        }
    }
    // TODO: optimize for cache localily
    /// builds lookups from the table using the index in the structure
    pub fn lookups(&self, table: &[F]) -> Vec<F> {
        let mut lookups = Vec::with_capacity(table.len());
        for lookup in self.lookups.iter() {
            lookups.push(table[*lookup]);
        }
        lookups
    }
}

fn normal_index<F: Field>(n: usize) -> Vec<F> {
    successors(Some(0_u32), |x| Some(x + 1))
        .map(F::from)
        .take(n)
        .collect()
}

impl<F: Field, const D: usize> SparkStructure<F, D> {
    pub fn new(evals: Vec<([usize; D], F)>) -> Self {
        let len = evals.len();
        assert!(len.is_power_of_two(), "must be power of 2");
        let mut counts = [(); D].map(|_| vec![0; len]);
        let mut lookups = [(); D].map(|_| Vec::with_capacity(len));
        let mut vals = Vec::with_capacity(len);
        for (point, val) in evals {
            for i in 0..D {
                assert!(point[i] < len, "index out of bound");
                //TODO: values other than 1 still work, not sure if it should be the case
                counts[i][point[i]] += 1;
                lookups[i].push(point[i]);
            }
            vals.push(val);
        }
        let dimensions = counts
            .into_iter()
            .zip(lookups)
            .map(|(counts, lookups)| {
                let dim = DimensionStructure::new(counts, lookups);
                dim
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let normal_index = normal_index(len);
        let val = vals;
        Self {
            dimensions,
            normal_index,
            val,
        }
    }
}
