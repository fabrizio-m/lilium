use crate::instances::lcs::{
    key::LcsProvingKey, reduction_proving::ReducedInstanceWitness, verifying::LcsProof, LcsInstance,
};
use ark_ff::Field;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use transcript::Transcript;

impl<F: Field, C: CommmitmentScheme<F>, const IO: usize> LcsProvingKey<F, C, IO> {
    pub fn prove<S, const I: usize>(
        key: LcsProvingKey<F, C, IO>,
        instance: LcsInstance<F, C, I>,
        witness: Vec<F>,
        transcript: &mut Transcript<F, S>,
    ) -> LcsProof<F, C, IO>
    where
        S: Duplex<F>,
        C: 'static,
    {
        let ReducedInstanceWitness {
            linearized_instance: _,
            linearized_witness: _,
            reduction_proof: _,
        } = Self::reduce_instance_witness(key, instance, witness, transcript);

        todo!()
    }
}
