use crate::instances::{
    lcs::{sumcheck_argument::LcsMles, LcsSumcheck},
    linearized::sumcheck_argument::LinearizedMles,
};
use ark_ff::Field;
use ccs::witness::LinearCombinations;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use std::rc::Rc;
use sumcheck::polynomials::MultiPoint;
use transcript::{params::ParamResolver, Message};

//TODO: rename as verifying
pub mod proving;
mod reduction_proving;
pub mod sumcheck_argument;

/// A linearized committed ccs instance
pub struct LinearizedInstance<F: Field, C: CommmitmentScheme<F>, const IO: usize, const S: usize> {
    /// C = commit(w).
    pub witness_commit: C::Commitment,
    pub witness_eval: F,
    /// Random point to indirectly eval the matrices.
    pub rx: MultiPoint<F>,
    /// The sum of the resulting vector from each matrix multiplication.
    pub products: [F; IO],
    /// Evals of selectors to be checked.
    pub selector_evals: [F; S],
}

pub struct Key<F: Field, C: CommmitmentScheme<F>, const IO: usize, const S: usize> {
    domain_vars: usize,
    selector_commitments: CommittedStructure<F, LcsSumcheck<F, IO, S>, C>,
    linear_combinations: Rc<LinearCombinations<IO>>,
    structure: Rc<Vec<LinearizedMles<F, IO>>>,
    lcs_structure: Rc<Vec<LcsMles<F, IO, S>>>,
    pcs: Rc<C>,
}

impl<F, C, const IO: usize, const S: usize> Message<F> for LinearizedInstance<F, C, IO, S>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        let commit = C::Commitment::len(vars, param_resolver);
        commit + 1 + vars + IO + S
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = self.witness_commit.to_field_elements();
        elems.push(self.witness_eval);
        elems.extend_from_slice(&self.rx.to_field_elements());
        elems.extend_from_slice(&self.products);
        elems.extend_from_slice(&self.selector_evals);
        elems
    }
}
