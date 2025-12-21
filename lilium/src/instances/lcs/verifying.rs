use super::reduction::LcsReductionProof;
use crate::{
    instances::{
        lcs::{key::LcsProvingKey, reduction::LcsReduction, LcsInstance, LcsProver},
        linearized::proving::{LinearizedInstanceReduction, LinearizedProof},
    },
    proving::matrix_eval::{MatrixEvalProof, MatrixEvalProtocol},
};
use ark_ff::Field;
use commit::CommmitmentScheme;
use transcript::{
    protocols::{Protocol, Reduction},
    MessageGuard, TranscriptBuilder, TranscriptGuard,
};

pub struct LcsProof<F: Field, C: CommmitmentScheme<F>, const IO: usize> {
    reduction_proof: LcsReductionProof<F, IO>,
    linearized_proof: LinearizedProof<F, IO>,
    matrix_eval_proof: MatrixEvalProof<F, C, IO>,
    open_proofs: [C::Proof; 2],
}

impl<F: Field, C: CommmitmentScheme<F>, const IO: usize> LcsProof<F, C, IO> {
    pub(crate) fn new(
        reduction_proof: LcsReductionProof<F, IO>,
        linearized_proof: LinearizedProof<F, IO>,
        matrix_eval_proof: MatrixEvalProof<F, C, IO>,
        open_proofs: [C::Proof; 2],
    ) -> Self {
        Self {
            reduction_proof,
            linearized_proof,
            matrix_eval_proof,
            open_proofs,
        }
    }
}

impl<F, C, const I: usize, const IO: usize> Protocol<F> for LcsProver<C, I, IO>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type Key = LcsProvingKey<F, C, IO>;

    //TODO: add input size
    type Instance = LcsInstance<F, C, I>;

    type Proof = LcsProof<F, C, IO>;

    type Error = ();

    fn transcript_pattern(builder: TranscriptBuilder) -> TranscriptBuilder {
        builder
            .add_reduction_patter::<F, LcsReduction<C, I, IO>>()
            .add_reduction_patter::<F, LinearizedInstanceReduction<F, C, IO, 4>>()
            .add_protocol_patter::<F, MatrixEvalProtocol<F, C, IO>>()
            .add_protocol_patter::<F, C>()
            .add_protocol_patter::<F, C>()
    }

    fn prove(_instance: Self::Instance) -> Self::Proof {
        todo!()
    }

    fn verify<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::Instance>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<(), Self::Error> {
        let lcs_reduction_proof =
            transcript.receive_message_delayed(|proof| proof.reduction_proof.clone());
        let reduced = LcsReduction::verify_reduction(
            &key.lcs_reduction_key,
            instance,
            transcript.new_guard(lcs_reduction_proof),
        )
        .unwrap();
        let linearized_instance = reduced;

        let linearized_instance = MessageGuard::new(linearized_instance);
        let linearized_proof =
            transcript.receive_message_delayed(|proof| proof.linearized_proof.clone());
        let proof = linearized_proof;
        let reduced = LinearizedInstanceReduction::verify_reduction(
            &key.linearized_reduction_key,
            linearized_instance,
            transcript.new_guard(proof),
        )
        .unwrap();
        let (matrix_eval_instance, open_instances) = reduced;

        let matrix_eval_instance = MessageGuard::new(matrix_eval_instance);
        let proof = transcript.receive_message_delayed(|proof| proof.matrix_eval_proof.clone());
        MatrixEvalProtocol::verify(
            &key.matrix_eval_key,
            matrix_eval_instance,
            transcript.new_guard(proof),
        )
        .unwrap();

        let scheme = &key.pcs;

        let [open_instance1, open_instance2] = open_instances;
        let proof = transcript.receive_message_delayed(|proof| proof.open_proofs[0].clone());
        let instance = MessageGuard::new(open_instance1);
        C::verify(scheme, instance, transcript.new_guard(proof)).unwrap();

        let proof = transcript.receive_message_delayed(|proof| proof.open_proofs[1].clone());
        let instance = MessageGuard::new(open_instance2);
        C::verify(scheme, instance, transcript.new_guard(proof)).unwrap();
        Ok(())
    }
}
