use std::rc::Rc;

use crate::{
    instances::{lcs::sumcheck_argument::LcsSumcheck, linearized},
    proving::matrix_eval,
};
use ark_ff::Field;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};

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
    pub linearized_reduction_key: linearized::Key<F, C, IO>,
    pub matrix_eval_key: matrix_eval::Key<F, C, IO>,
    pub pcs: Rc<C>,
}
