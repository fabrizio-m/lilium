use crate::{
    flcs::FlcsReductionKey,
    instances::{lcs::sumcheck_argument::LcsMles, linearized},
    proving::matrix_eval,
};
use ark_ff::Field;
use ccs::{
    structure::{Exp, Matrix},
    witness::LinearCombinations,
};
use commit::CommmitmentScheme;
use spark::committed_spark::CommittedSpark;
use std::rc::Rc;

pub struct LcsProvingKey<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub flcs_reduction_key: FlcsReductionKey<F, IO>,
    pub linearized_reduction_key: linearized::Key<F, C, IO, 4>,
    pub matrix_eval_key: matrix_eval::Key<F, C, IO>,
    pub pcs: Rc<C>,
}

impl<F, C, const IO: usize> LcsProvingKey<F, C, IO>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub fn new(
        pcs: Rc<C>,
        structure: Rc<Vec<LcsMles<F, IO, 4>>>,
        matrices: [Rc<Matrix>; IO],
        spark_keys: [CommittedSpark<F, C, 2>; IO],
        gates: Vec<Vec<Exp<usize>>>,
    ) -> Self {
        let linear_combinations = {
            let matrices: [&Matrix; IO] = matrices.each_ref().map(AsRef::as_ref);
            let linear_combinations = LinearCombinations::from_tables(matrices);
            Rc::new(linear_combinations)
        };
        let flcs_reduction_key = FlcsReductionKey::new(
            Rc::clone(&structure),
            Rc::clone(&linear_combinations),
            gates.clone(),
        );
        let domain_vars = flcs_reduction_key.domain_vars;
        let linearized_reduction_key = linearized::Key::new(
            domain_vars,
            Rc::clone(&structure),
            Rc::clone(&pcs),
            matrices,
        );
        let matrix_eval_key = matrix_eval::Key::new(spark_keys, Rc::clone(&pcs));
        Self {
            flcs_reduction_key,
            linearized_reduction_key,
            matrix_eval_key,
            pcs,
        }
    }
}
