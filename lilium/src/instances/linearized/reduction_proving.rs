use crate::instances::{
    lcs::sumcheck_argument::LcsMles,
    linearized::{
        proving::LinearizedProof,
        sumcheck_argument::{LinearizedSumcheck, SingleChall},
        LinearizedInstance,
    },
    matrix_eval::BatchMatrixEvalInstance,
};
use ark_ff::Field;
use ccs::witness::LinearCombinations;
use commit::{batching::structured::StructuredBatchEval, CommmitmentScheme, OpenInstance};
use sponge::sponge::Duplex;
use sumcheck::{eq, polynomials::MultiPoint, sumcheck::SumcheckProver};
use transcript::{messages::SingleElement, Transcript};

pub(crate) struct ProverOutput<F, C, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub matrix_eval_instance: BatchMatrixEvalInstance<F, IO>,
    pub open_instances: [OpenInstance<F, C::Commitment>; 2],
    pub open_witnesses: [Vec<F>; 2],
    pub proof: LinearizedProof<F, IO>,
}

impl<F, C, const IO: usize, const S: usize> super::Key<F, C, IO, S>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    pub(crate) fn prove<const I: usize, D>(
        &self,
        instance: LinearizedInstance<F, C, IO, S>,
        witness: Vec<F>,
        transcript: &mut Transcript<F, D>,
    ) -> ProverOutput<F, C, IO>
    where
        D: Duplex<F>,
    {
        //TODO:handle
        let [chall] = transcript.send_message(&instance).unwrap();
        //TODO: Use all fields to check the results are as expected.
        let LinearizedInstance {
            witness_commit,
            witness_eval: _,
            rx,
            products: _,
            selector_evals: _,
        } = instance;

        //TODO: add vars
        let sumcheck_prover: SumcheckProver<F, LinearizedSumcheck<IO>> = SumcheckProver::new(16);

        //TODO: it isn't strictly necessary to keep 2 copies.
        let mles = self.mles(&witness, &rx);
        let challs = SingleChall(chall);
        let sumcheck::sumcheck::ProverOutput {
            point: ry,
            proof: sumcheck_proof,
            evals,
        } = sumcheck_prover
            .prove(transcript, mles.clone(), &challs)
            .unwrap();

        let (committed_open_instance, mles) =
            self.lcs_open_instance(&witness, witness_commit.clone(), rx.clone());
        let (open_instance_rx, folded_mle_rx) =
            self.selector_commitments
                .prove(committed_open_instance, &mles, transcript);

        // let w_eval_rx = SingleElement(witness_eval);
        let open_instance_ry = self.pcs.open_instance(witness_commit, ry.clone(), &witness);
        let w_eval_ry = SingleElement(open_instance_ry.eval());

        //TODO: handle
        let [] = transcript.send_message(&w_eval_ry).unwrap();

        let (matrix_evals, matrix_eval_instance) = {
            // As product = w * M, and we know w, then M = product/w
            let w_eval_inverse = w_eval_ry.0.inverse().expect("shouldn't evaluate to 0");
            let matrix_evals = evals.products.map(|p| p * w_eval_inverse);

            let instance = BatchMatrixEvalInstance {
                matrix_evals,
                point: [rx, ry],
            };
            let matrix_evals = matrix_evals.map(SingleElement);
            //TODO: handle
            let [] = transcript.send_message(&matrix_evals).unwrap();

            (matrix_evals, instance)
        };

        let open_instances = [open_instance_rx, open_instance_ry];
        let proof = LinearizedProof {
            sumcheck_proof,
            w_eval: w_eval_ry,
            matrix_evals,
        };
        ProverOutput {
            matrix_eval_instance,
            open_instances,
            open_witnesses: [folded_mle_rx, witness],
            proof,
        }
    }

    fn mles(&self, witness: &[F], r_eq: &MultiPoint<F>) -> Vec<LinearizedMles<F, IO>> {
        let structure = &self.structure;
        let linear_combinations = &self.linear_combinations;
        fill_mles(structure, linear_combinations, witness, r_eq)
    }

    fn lcs_open_instance(
        &self,
        w: &[F],
        w_commit: C::Commitment,
        point: MultiPoint<F>,
    ) -> (StructuredBatchEval<F, C>, Vec<LcsMles<F, IO, S>>) {
        //TODO: optimize memory use.
        let commit = self.selector_commitments.instance_commit(vec![w_commit]);
        let mut mles: Vec<_> = self.lcs_structure.as_slice().to_vec();
        assert_eq!(mles.len(), w.len());
        for (row, w) in mles.iter_mut().zip(w.iter()) {
            let row: &mut LcsMles<F, IO, S> = row;
            row.set_w(*w);
        }
        (
            self.selector_commitments
                .open_instance(commit, mles.clone(), point),
            mles,
        )
    }
}

use super::sumcheck_argument::LinearizedMles;

fn fill_mles<F, const IO: usize>(
    structure: &[LinearizedMles<F, IO>],
    linear_combinations: &LinearCombinations<IO>,
    witness: &[F],
    r_eq: &MultiPoint<F>,
) -> Vec<LinearizedMles<F, IO>>
where
    F: Field,
{
    let mut mles = structure.to_vec();
    let mut combinations = linear_combinations.compute(witness);
    let r_eq = eq::eq(r_eq);

    for i in 0..mles.len() {
        let products: [F; IO] = combinations.next().unwrap();

        let row: &mut LinearizedMles<F, IO> = &mut mles[i];
        row.products = products;
        row.r_eq = r_eq[i];
    }
    mles
}
