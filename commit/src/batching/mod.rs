use crate::CommmitmentScheme2;
use ark_ff::Field;
use sumcheck::polynomials::MultiPoint;
use transcript::Message;

pub mod reduction;
pub mod structured;

/// Batch evaluation instance
pub struct BatchEval<F: Field, S: CommmitmentScheme2<F>> {
    point: MultiPoint<F>,
    commitments_and_evals: Vec<(S::Commitment, F)>,
}

impl<F: Field, S: CommmitmentScheme2<F>> BatchEval<F, S> {
    pub(crate) fn new(
        point: MultiPoint<F>,
        commitments_and_evals: Vec<(S::Commitment, F)>,
    ) -> Self {
        Self {
            point,
            commitments_and_evals,
        }
    }
}

pub enum BatchingError<E> {
    Transcript(transcript::Error),
    /// Inner PCS error
    Pcs(E),
}

pub struct CommitsNumber;

impl<F: Field, S: CommmitmentScheme2<F>> Message<F> for BatchEval<F, S> {
    fn len(vars: usize, param_resolver: &transcript::params::ParamResolver) -> usize {
        let point = vars;
        let commits = param_resolver.get::<CommitsNumber>();
        let single_commit_len = S::Commitment::len(vars, param_resolver);
        point + (single_commit_len + 1) * commits
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = Vec::new();
        elems.extend(self.point.clone().inner());
        for commit_and_eval in &self.commitments_and_evals {
            let (commit, eval) = commit_and_eval;
            elems.extend(commit.to_field_elements());
            elems.push(*eval);
        }
        elems
    }
}
