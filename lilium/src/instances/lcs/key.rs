use crate::{
    instances::{
        lcs::sumcheck_argument::{LcsMles, LcsSumcheck},
        linearized,
    },
    proving::matrix_eval,
};
use ark_ff::Field;
use ccs::witness::LinearCombinations;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use std::rc::Rc;

pub struct LcsReductionKey<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub committed_structure: CommittedStructure<F, LcsSumcheck<F, IO, 4>, C>,
    pub domain_vars: usize,
}

pub struct LcsProvingKey<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub lcs_reduction_key: LcsReductionKey<F, C, IO>,
    pub linear_combinations: LinearCombinations<IO>,
    pub linearized_reduction_key: linearized::Key<F, C, IO, 4>,
    pub matrix_eval_key: matrix_eval::Key<F, C, IO>,
    pub pcs: Rc<C>,
    /// MLEs where structure is set as expected and non-structure
    /// MLEs are set to 0.
    pub mles: Rc<Vec<LcsMles<F, IO, 4>>>,
}
