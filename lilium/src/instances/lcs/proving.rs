use crate::{
    flcs::ReducedInstanceWitness,
    instances::{
        lcs::{
            key::LcsProvingKey, verifying::LcsProof, zerocheck_reduction::ZerocheckReductionKey,
            LcsInstance,
        },
        linearized::reduction_proving,
    },
};
use ark_ff::Field;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use transcript::Transcript;

impl<F: Field, C: CommmitmentScheme<F>, const IO: usize> LcsProvingKey<F, C, IO> {
    pub fn prove<S, const I: usize>(
        &self,
        instance: LcsInstance<F, C, I>,
        witness: Vec<F>,
        transcript: &mut Transcript<F, S>,
    ) -> LcsProof<F, C, IO>
    where
        S: Duplex<F>,
        C: 'static,
    {
        let vars = self.flcs_reduction_key.domain_vars;
        let zerocheck_key = ZerocheckReductionKey::new(vars);
        let instance = zerocheck_key.reduce::<F, C, S, I>(instance, transcript);

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
        } = self.linearized_reduction_key.prove::<I, S>(
            linearized_instance,
            linearized_witness,
            transcript,
        );

        let matrix_eval_proof = self
            .matrix_eval_key
            .prove(matrix_eval_instance, transcript)
            .unwrap();

        let [open_rx, open_ry] = open_instances;
        let open_proof_rx = self
            .pcs
            .open_prove(open_rx, &open_witnesses[0], transcript)
            .unwrap();
        let open_proof_ry = self
            .pcs
            .open_prove(open_ry, &open_witnesses[1], transcript)
            .unwrap();

        let open_proofs = [open_proof_rx, open_proof_ry];
        LcsProof::new(
            reduction_proof,
            linearized_proof,
            matrix_eval_proof,
            open_proofs,
        )
    }
}
