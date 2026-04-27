use crate::{
    flcs::FlcsReductionKey,
    instances::{lcs::sumcheck_argument::LcsMles, linearized},
    proving::matrix_eval2,
};
use ark_ff::Field;
use ccs::{
    structure::{Exp, Matrix},
    witness::LinearCombinations,
};
use commit::{batching::multipoint::MultipointBatching, CommmitmentScheme};
use std::rc::Rc;
use sumcheck::sumcheck::SumcheckVerifier;

pub struct LcsProvingKey<F, C, const IO: usize, const S: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub flcs_reduction_key: FlcsReductionKey<F, IO, S>,
    pub linearized_reduction_key: linearized::Key<F, C, IO, S>,
    pub matrix_eval_key: matrix_eval2::Key<F, C, IO>,
    pub pcs: Rc<C>,
    pub batching: SumcheckVerifier<F, MultipointBatching<C, 3>>,
}

impl<F, C, const IO: usize, const S: usize> LcsProvingKey<F, C, IO, S>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    pub fn new(
        pcs: Rc<C>,
        structure: Rc<Vec<LcsMles<F, IO, S>>>,
        matrices: [Rc<Matrix>; IO],
        spark_evals: [Vec<([usize; 2], F)>; IO],
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
        let matrix_eval_key = matrix_eval2::Key::new(spark_evals, Rc::clone(&pcs));

        let batching = SumcheckVerifier::new_symbolic(MultipointBatching::default(), domain_vars);
        Self {
            flcs_reduction_key,
            linearized_reduction_key,
            matrix_eval_key,
            pcs,
            batching,
        }
    }
}
