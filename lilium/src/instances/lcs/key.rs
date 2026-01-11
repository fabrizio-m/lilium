use crate::{
    instances::{
        lcs::sumcheck_argument::{LcsMles, LcsSumcheck},
        linearized,
    },
    proving::matrix_eval,
};
use ark_ff::Field;
use ccs::{
    structure::{Exp, Matrix},
    witness::LinearCombinations,
};
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use spark::committed_spark::CommittedSpark;
use std::rc::Rc;
use sumcheck::sumcheck::SumcheckVerifier;

pub struct LcsReductionKey<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub committed_structure: CommittedStructure<F, LcsSumcheck<F, IO, 4>, C>,
    pub domain_vars: usize,
    pub sumcheck_verifier: SumcheckVerifier<F, LcsSumcheck<F, IO, 4>>,
}

impl<F, C, const IO: usize> LcsReductionKey<F, C, IO>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    // pub fn new<const S: usize>(
    pub fn new(
        // structure: Rc<Vec<LcsMles<F, IO, S>>>,
        structure: Rc<Vec<LcsMles<F, IO, 4>>>,
        gates: Vec<Vec<Exp<usize>>>,
        pcs: &C,
    ) -> Self {
        let domain_vars = structure.len().next_power_of_two().ilog2() as usize;
        let committed_structure = CommittedStructure::new(structure, pcs);

        let f = LcsSumcheck::new(gates);
        let sumcheck_verifier = SumcheckVerifier::new_symbolic(&f, domain_vars);
        Self {
            committed_structure,
            domain_vars,
            sumcheck_verifier,
        }
    }
}

pub struct LcsProvingKey<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub lcs_reduction_key: LcsReductionKey<F, C, IO>,
    pub linear_combinations: Rc<LinearCombinations<IO>>,
    pub linearized_reduction_key: linearized::Key<F, C, IO, 4>,
    pub matrix_eval_key: matrix_eval::Key<F, C, IO>,
    pub pcs: Rc<C>,
    /// MLEs where structure is set as expected and non-structure
    /// MLEs are set to 0.
    pub mles: Rc<Vec<LcsMles<F, IO, 4>>>,
}

impl<F, C, const IO: usize> LcsProvingKey<F, C, IO>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub fn new(
        pcs: Rc<C>,
        structure: Rc<Vec<LcsMles<F, IO, 4>>>,
        matrices: [&Matrix; IO],
        spark_keys: [CommittedSpark<F, C, 2>; IO],
        gates: Vec<Vec<Exp<usize>>>,
    ) -> Self {
        let lcs_reduction_key = LcsReductionKey::new(Rc::clone(&structure), gates, pcs.as_ref());
        let domain_vars = lcs_reduction_key.domain_vars;
        let linear_combinations = LinearCombinations::from_tables(matrices);
        let linear_combinations = Rc::new(linear_combinations);
        let linearized_reduction_key = linearized::Key::new(
            domain_vars,
            Rc::clone(&linear_combinations),
            Rc::clone(&structure),
            Rc::clone(&pcs),
        );
        let matrix_eval_key = matrix_eval::Key::new(spark_keys, Rc::clone(&pcs));
        let mles = structure;
        Self {
            lcs_reduction_key,
            linear_combinations,
            linearized_reduction_key,
            matrix_eval_key,
            pcs,
            mles,
        }
    }
}
