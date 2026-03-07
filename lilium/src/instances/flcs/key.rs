use crate::instances::flcs::sumcheck_reduction::{LcsMles, LcsSumcheck};
use crate::instances::lcs::sumcheck_argument;
use ark_ff::Field;
use ccs::structure::Exp;
use ccs::witness::LinearCombinations;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use std::rc::Rc;
use sumcheck::{
    sumcheck::{SumcheckProver, SumcheckVerifier},
    zerocheck::ZeroCheckMles,
};

pub struct FlcsReductionKey<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub committed_structure: CommittedStructure<F, LcsSumcheck<F, IO, 4>, C>,
    pub domain_vars: usize,
    pub sumcheck_verifier: SumcheckVerifier<F, LcsSumcheck<F, IO, 4>>,
    pub sumcheck_prover: SumcheckProver<F, LcsSumcheck<F, IO, 4>>,
    pub structure: Rc<Vec<ZeroCheckMles<F, LcsMles<F, IO, 4>>>>,
    pub linear_combinations: Rc<LinearCombinations<IO>>,
}

impl<F, C, const IO: usize> FlcsReductionKey<F, C, IO>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub fn new(
        structure: Rc<Vec<sumcheck_argument::LcsMles<F, IO, 4>>>,
        linear_combinations: Rc<LinearCombinations<IO>>,
        gates: Vec<Vec<Exp<usize>>>,
        pcs: &C,
    ) -> Self {
        let domain_vars = structure.len().next_power_of_two().ilog2() as usize;
        let sumcheck_function = LcsSumcheck::new(gates);
        let structure = structure
            .iter()
            .map(|inner| {
                let (input_selector, gate_selectors) = inner.selectors();
                let inner = LcsMles::new_structure(input_selector, gate_selectors);
                ZeroCheckMles::new(F::zero(), inner)
            })
            .collect();
        let structure = Rc::new(structure);

        let sumcheck_prover = SumcheckProver::new_symbolic(domain_vars, &sumcheck_function);
        let sumcheck_verifier = SumcheckVerifier::new_symbolic(sumcheck_function, domain_vars);
        let committed_structure = CommittedStructure::new(Rc::clone(&structure), pcs);
        Self {
            committed_structure,
            domain_vars,
            sumcheck_verifier,
            sumcheck_prover,
            structure,
            linear_combinations,
        }
    }
}
