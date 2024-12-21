use crate::CommmitmentScheme;
use ark_ff::Field;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::SumcheckFunction,
};

pub struct CommittedStructure<F, SF, CS>
where
    F: Field,
    SF: SumcheckFunction<F>,
    CS: CommmitmentScheme<F>,
{
    structure: SF::Mles<usize>,
    commitments: Vec<CS::Commitment>,
    mles: Vec<Vec<F>>,
}

impl<F, SF, CS> CommittedStructure<F, SF, CS>
where
    F: Field,
    SF: SumcheckFunction<F>,
    CS: CommmitmentScheme<F>,
{
    pub fn commit(scheme: &CS, mles: Vec<SF::Mles<F>>) -> Self {
        //TODO: for now assuming all evals are committed
        //to know the length
        let (len, structure) = {
            let sample = SF::eval_kinds().flatten_vec();
            let len = sample.len();
            let mut structure = sample.iter().enumerate().map(|(i, _)| i).collect();
            let structure = SF::Mles::<usize>::unflatten(&mut structure);
            (len, structure)
        };
        let capacity = mles.len();
        let mut mles_flat = vec![Vec::with_capacity(capacity); len];
        let mut temp = vec![];
        for point in mles.into_iter() {
            let evals: SF::Mles<F> = point;
            evals.flatten(&mut temp);
            for i in 0..len {
                mles_flat[i].push(temp[i]);
            }
            temp.truncate(0);
        }
        let commitments = mles_flat.iter().map(|mle| scheme.commit_mle(mle)).collect();
        let mles = mles_flat;

        Self {
            structure,
            commitments,
            mles,
        }
    }
    pub fn eval(&self, scheme: &CS, point: &MultiPoint<F>) -> (Vec<CS::OpenProof>, SF::Mles<F>) {
        let mut evals = vec![];
        let mut proofs = vec![];
        for i in 0..self.commitments.len() {
            let mle = &self.mles[i];
            let commitment = self.commitments[i].clone();
            let (eval, opening) = scheme.open(mle, commitment, point, None);
            proofs.push(opening);
            evals.push(eval);
        }
        let evals = SF::Mles::<_>::unflatten_vec(evals);
        (proofs, evals)
    }
    pub fn verify(
        &self,
        scheme: &CS,
        point: &MultiPoint<F>,
        proofs: Vec<CS::OpenProof>,
        evals: SF::Mles<F>,
    ) -> bool {
        let mut evals = evals.flatten_vec().into_iter();
        let mut proofs = proofs.into_iter();
        //TODO: only work with all evals being commit
        if proofs.len() != evals.len() {
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
