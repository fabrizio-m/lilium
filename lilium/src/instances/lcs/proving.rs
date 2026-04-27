use crate::{
    flcs::ReducedInstanceWitness,
    instances::{
        lcs::{
            key::LcsProvingKey, verifying::LcsProof, zerocheck_reduction::ZerocheckReductionKey,
            LcsInstance,
        },
        linearized::reduction_proving,
    },
    proving::matrix_eval2,
};
use ark_ff::Field;
use commit::{
    batching::multipoint::{self, MultipointBatching},
    CommmitmentScheme,
};
use sponge::sponge::Duplex;
use transcript::Transcript;

impl<F: Field, C: CommmitmentScheme<F>, const IO: usize, const S: usize>
    LcsProvingKey<F, C, IO, S>
{
    pub fn prove<D, const I: usize>(
        &self,
        instance: LcsInstance<F, C, I>,
        witness: Vec<F>,
        transcript: &mut Transcript<F, D>,
    ) -> LcsProof<F, C, IO, S>
    where
        D: Duplex<F>,
        C: 'static,
    {
        let vars = self.flcs_reduction_key.domain_vars;
        let zerocheck_key = ZerocheckReductionKey::new(vars);
        let instance = zerocheck_key.reduce::<F, C, D, I>(instance, transcript);

        let ReducedInstanceWitness {
            linearized_instance,
            linearized_witness,
            reduction_proof,
        } = self
            .flcs_reduction_key
            .reduce_foldable_instance_witness(instance, witness, transcript);

        let reduction_proving::ProverOutput {
            matrix_eval_instance,
            open_instances,
            open_witnesses,
            proof: linearized_proof,
        } = self.linearized_reduction_key.prove::<I, D>(
            linearized_instance,
            linearized_witness,
            transcript,
        );

        let matrix_eval2::ProverOutput {
            matrix_eval_proof,
            open_instance,
            open_witness,
        } = self
            .matrix_eval_key
            .prove(matrix_eval_instance, transcript)
            .unwrap();

        let [open_rx, open_ry] = open_instances;
        let instance = [open_rx, open_ry, open_instance];
        let [w1, w2] = open_witnesses;
        let witness = [w1, w2, open_witness];

        let multipoint::ProverOutput {
            instance,
            witness,
            proof: batching_proof,
        } = MultipointBatching::prove(instance, witness, transcript);

        let open_proof = self.pcs.open_prove(instance, &witness, transcript).unwrap();

        LcsProof::new(
            reduction_proof,
            linearized_proof,
            matrix_eval_proof,
            batching_proof,
            open_proof,
        )
    }
}
