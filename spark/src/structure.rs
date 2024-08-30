//! definitions for static commitments

use ark_ff::Field;

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
