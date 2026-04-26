use ark_ff::Field;
use sponge::sponge::Duplex;
use sumcheck::{eq, sumcheck::SumcheckProver};
use transcript::{messages::SingleElement, Transcript};

use crate::{
    batching::multipoint::{
        reduction::BatchingProof, MultipointBatching, MultipointChall, MultipointEvals,
    },
    CommmitmentScheme, OpenInstance,
};

pub struct ProverOutput<F: Field, C: CommmitmentScheme<F>, const N: usize> {
    pub instance: OpenInstance<F, C::Commitment>,
    pub witness: Vec<F>,
    pub proof: BatchingProof<F, C, N>,
}

impl<C, const N: usize> MultipointBatching<C, N> {
    pub fn prove<F, S>(
        instance: [OpenInstance<F, C::Commitment>; N],
        witness: [Vec<F>; N],
        transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<F, C, N>
    where
        F: Field,
        S: Duplex<F>,
        C: CommmitmentScheme<F> + 'static,
    {
        // let (instance, [chall]) = transcript.unwrap_guard(instance)?;
        let [chall] = transcript.send_message(&instance).unwrap();

        let zero = [MultipointEvals {
            eq: F::zero(),
            poly: F::zero(),
        }; N];
        let mut mles = vec![zero; witness[0].len()];

        for (i, witness) in witness.iter().enumerate() {
            for (e, w) in mles.iter_mut().zip(witness) {
                e[i].poly = *w;
            }
            let eq = eq::eq(&instance[i].point);
            for (e, eq) in mles.iter_mut().zip(eq) {
                e[i].eq = eq;
            }
        }

        let vars = mles.len().next_power_of_two().ilog2() as usize;
        let sumcheck_prover: SumcheckProver<F, MultipointBatching<C, N>> =
            SumcheckProver::new_symbolic(vars, &MultipointBatching::default());

        let challs = MultipointChall(chall);
        let reduced = sumcheck_prover
            .prove_symbolic(transcript, mles, &challs)
            .unwrap();

        let evals = reduced.evals.map(|e| e.poly);
        let evals_message = evals.map(SingleElement);

        let [chall] = transcript.send_message(&evals_message).unwrap();

        let mut evals_and_commits = evals
            .into_iter()
            .zip(instance)
            .map(|(eval, open)| (eval, open.commit));
        let first = evals_and_commits.next().unwrap();
        let (eval, commit) = evals_and_commits.fold(first, |acc, e| {
            let eval = acc.0 * chall + e.0;
            let commit = acc.1 * chall + e.1;
            (eval, commit)
        });

        let point = reduced.point;

        let instance = OpenInstance::new(commit, point, eval);
        let proof = BatchingProof::new(reduced.proof, evals);

        let witness = witness[1..].iter().fold(witness[0].clone(), |mut w1, w2| {
            for (w1, w2) in w1.iter_mut().zip(w2) {
                *w1 = *w1 * chall + w2;
            }
            w1
        });

        ProverOutput {
            instance,
            witness,
            proof,
        }
    }
}
