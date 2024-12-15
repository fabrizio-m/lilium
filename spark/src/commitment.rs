use crate::structure::{DimensionStructure, SparkStructure};
use ark_ff::Field;

/// commitmment to a sparse polynomial
pub struct SparkCommitment<C, const D: usize> {
    pub dimensions: [DimensionCommitment<C>; D],
    pub normal_index: C,
    pub val: C,
}

/// commitments corresponding to a given dimension
pub struct DimensionCommitment<C> {
    pub counts: C,
    pub lookups: C,
}

impl<C, const D: usize> SparkCommitment<C, D> {
    /// Commits to each MLE using the provided function
    pub fn from_structure<F: Field, S: Fn(Vec<F>) -> C>(
        structure: SparkStructure<F, D>,
        scheme: S,
    ) -> Self {
        let SparkStructure {
            dimensions,
            normal_index,
            val,
        } = structure;
        let val = scheme(val);
        let normal_index = scheme(normal_index);
        let dimensions = dimensions.map(|dim| {
            let DimensionStructure {
                counts_field,
                lookups_field,
                ..
            } = dim;
            let counts = scheme(counts_field);
            let lookups = scheme(lookups_field);
            DimensionCommitment { counts, lookups }
        });
        SparkCommitment {
            dimensions,
            normal_index,
            val,
        }
    }
}
