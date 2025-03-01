use crate::CommmitmentScheme;
use ark_ff::Field;
use std::convert::identity;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::{EvalKind, SumcheckFunction},
};

/// type generalizing the handling of commitment to structures, allowing
/// to commit to a strucuture based on a [SumcheckFunction] implementor.
/// Also allows to open all the commitments in a given point and verify
/// the opening proofs.
#[derive(Clone, Debug)]
pub struct CommittedStructure<F, SF, CS>
where
    F: Field,
    SF: SumcheckFunction<F>,
    CS: CommmitmentScheme<F>,
{
    structure: SF::Mles<Option<usize>>,
    commitments: Vec<CS::Commitment>,
    mles: Vec<Vec<F>>,
}

impl<F, SF, CS> CommittedStructure<F, SF, CS>
where
    F: Field,
    SF: SumcheckFunction<F>,
    CS: CommmitmentScheme<F>,
{
    /// builds the structure for only the committed evals with Some(idx)
    /// pointing to the mles and commitments vectors, and None for other
    /// kinds.
    fn build_structure() -> (SF::Mles<Option<usize>>, usize) {
        let structure_flat = SF::eval_kinds().flatten_vec();
        let mut index = 0;
        let mut structure = vec![];
        for eval in structure_flat.into_iter() {
            let eval: EvalKind = eval;
            match eval {
                EvalKind::Committed => {
                    structure.push(Some(index));
                    index += 1;
                }
                EvalKind::FixedSmall | EvalKind::Virtual => {
                    structure.push(None);
                }
            }
        }
        let len = structure.len();
        let evals = SF::Mles::unflatten_vec(structure);
        (evals, len)
    }
    /// Commits to structure, irrelevant mles may be filled with zeros
    /// or any other value as they will be ignored when committing.
    pub fn commit(scheme: &CS, mles: Vec<SF::Mles<F>>) -> Self {
        let (structure, len) = Self::build_structure();
        // filter only evals which are committed
        let commit_evals: Vec<usize> = structure
            .flatten_vec()
            .into_iter()
            .filter_map(identity)
            .collect();
        let commit_len = commit_evals.len();
        let capacity = mles.len();
        let mut mles_flat = vec![Vec::with_capacity(capacity); commit_len];

        // copying the relevant mles into individual vectors
        let mut temp = vec![];
        for point in mles.into_iter() {
            let evals: SF::Mles<F> = point;
            evals.flatten(&mut temp);
            for i in 0..len {
                let idx = commit_evals[i];
                mles_flat[i].push(temp[idx]);
            }
            temp.truncate(0);
        }
        let commitments = mles_flat.iter().map(|mle| scheme.commit_mle(mle)).collect();
        let mles = mles_flat;

        let (structure, _) = Self::build_structure();
        Self {
            structure,
            commitments,
            mles,
        }
    }
    /// creates evaluation proofs and also provides only the evaluations
    /// of committed mles, and None for the rest.
    pub fn eval(
        &self,
        scheme: &CS,
        point: &MultiPoint<F>,
    ) -> (Vec<CS::OpenProof>, SF::Mles<Option<F>>) {
        let mut evals = vec![];
        let mut proofs = vec![];
        for i in 0..self.commitments.len() {
            let mle = &self.mles[i];
            let commitment = self.commitments[i].clone();
            let (eval, opening) = scheme.open(mle, commitment, point, None);
            proofs.push(opening);
            evals.push(eval);
        }
        let structure = self.structure.clone().flatten_vec();
        let mut evals = evals.into_iter();
        let evals: Vec<Option<F>> = structure
            .into_iter()
            .map(|x| x.map(|_| evals.next().unwrap()))
            .collect();
        let evals = SF::Mles::<_>::unflatten_vec(evals);
        (proofs, evals)
    }
    /// verifies output of eval() at given point
    pub fn verify(
        &self,
        scheme: &CS,
        point: &MultiPoint<F>,
        proofs: Vec<CS::OpenProof>,
        evals: SF::Mles<F>,
    ) -> bool {
        // filter the ones that are committed according to the structure
        let evals: Vec<F> = evals
            .flatten_vec()
            .into_iter()
            .zip(self.structure.clone().flatten_vec())
            .filter_map(|(eval, structure): (F, Option<usize>)| structure.map(|_| eval))
            .collect();
        let evals_len = evals.len();
        let mut evals = evals.into_iter();
        let mut proofs = proofs.into_iter();

        if proofs.len() != evals_len {
            return false;
        }

        for i in 0..evals.len() {
            let commitment = self.commitments[i].clone();
            let eval = evals.next().unwrap();
            let proof = proofs.next().unwrap();
            let verifies = scheme.verify(commitment, &point, eval, proof);
            if !verifies {
                return false;
            }
        }
        true
    }
}
