use crate::CommmitmentScheme;
use ark_ff::Field;
use sumcheck::{polynomials::MultiPoint, SumcheckError};
use transcript::Message;

pub mod multipoint;
pub mod reduction;
pub mod structured;

/// Batch evaluation instance
#[derive(Debug, Clone)]
pub struct BatchEval<F: Field, S: CommmitmentScheme<F>> {
    point: MultiPoint<F>,
    commitments_and_evals: Vec<(S::Commitment, F)>,
}

impl<F: Field, S: CommmitmentScheme<F>> BatchEval<F, S> {
    pub fn new(point: MultiPoint<F>, commitments_and_evals: Vec<(S::Commitment, F)>) -> Self {
        Self {
            point,
            commitments_and_evals,
        }
    }
}

#[derive(Debug, Clone)]
pub enum BatchingError<F: Field, C: CommmitmentScheme<F>> {
    Transcript(transcript::Error),
    /// Inner PCS error
    Pcs(C::Error),
    Sumcheck(SumcheckError),
    /// Failure checking sumcheck's claimed evaluation.
    EvalCheck,
}

impl<F: Field, C: CommmitmentScheme<F>> From<transcript::Error> for BatchingError<F, C> {
    fn from(value: transcript::Error) -> Self {
        Self::Transcript(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<SumcheckError> for BatchingError<F, C> {
    fn from(value: SumcheckError) -> Self {
        Self::Sumcheck(value)
    }
}

pub struct CommitsNumber;

impl<F: Field, S: CommmitmentScheme<F>> Message<F> for BatchEval<F, S> {
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
