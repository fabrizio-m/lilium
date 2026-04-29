use crate::instances::{
    lcs::{sumcheck_argument::LcsMles, LcsSumcheck},
    linearized::sumcheck_argument::LinearizedMles,
};
use ark_ff::Field;
use ccs::matrix::Matrix;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use std::rc::Rc;
use sumcheck::polynomials::MultiPoint;
use transcript::{params::ParamResolver, Message};

//TODO: rename as verifying
pub mod proving;
pub mod reduction_proving;
pub mod sumcheck_argument;

/// A linearized committed ccs instance
#[derive(Debug)]
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
    pub constants: F,
}

pub struct Key<F: Field, C: CommmitmentScheme<F>, const IO: usize, const S: usize> {
    domain_vars: usize,
    selector_commitments: CommittedStructure<F, LcsSumcheck<F, IO, S>, C>,
    structure: Rc<Vec<LinearizedMles<F, IO>>>,
    lcs_structure: Rc<Vec<LcsMles<F, IO, S>>>,
    pcs: Rc<C>,
    matrices: [Rc<Matrix>; IO],
}

impl<F, C, const IO: usize, const S: usize> Message<F> for LinearizedInstance<F, C, IO, S>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        let commit = C::Commitment::len(vars, param_resolver);
        commit + 1 + vars + IO + S + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = self.witness_commit.to_field_elements();
        elems.push(self.witness_eval);
        elems.extend_from_slice(&self.rx.to_field_elements());
        elems.extend_from_slice(&self.products);
        elems.extend_from_slice(&self.selector_evals);
        elems.push(self.constants);
        elems
    }
}

impl<F: Field, C: CommmitmentScheme<F>, const IO: usize, const S: usize> Key<F, C, IO, S> {
    pub fn new(
        domain_vars: usize,
        lcs_structure: Rc<Vec<LcsMles<F, IO, S>>>,
        pcs: Rc<C>,
        matrices: [Rc<Matrix>; IO],
    ) -> Self {
        let dummy = LinearizedMles {
            matrices: [F::zero(); IO],
            r_eq: F::zero(),
            z: F::zero(),
        };
        let mles = vec![dummy; 1 << domain_vars];
        let structure = Rc::new(mles);
        let selector_commitments = CommittedStructure::new(Rc::clone(&lcs_structure), pcs.as_ref());

        Self {
            domain_vars,
            selector_commitments,
            structure,
            lcs_structure,
            pcs,
            matrices,
        }
    }
}
