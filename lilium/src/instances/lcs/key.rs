use crate::instances::lcs::sumcheck_argument::LcsSumcheck;
use ark_ff::Field;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};

pub struct LcsKey<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub committed_structure: CommittedStructure<F, LcsSumcheck<F, IO, 4>, C>,
    pub domain_vars: usize,
}
