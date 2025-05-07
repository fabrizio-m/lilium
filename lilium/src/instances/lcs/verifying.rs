use crate::{
    circuit_key::KeySparkStructure,
    instances::lcs::{LcsInstance, LcsProver},
};
use ark_ff::Field;
use commit::CommmitmentScheme;
use transcript::{protocols::Protocol, MessageGuard, TranscriptBuilder, TranscriptGuard};

impl<F, K, C, const I: usize, const IO: usize> Protocol<F> for LcsProver<K, C, I, IO>
where
    F: Field,
    C: CommmitmentScheme<F>,
    K: KeySparkStructure<F, C, IO>,
{
    type Key = K;

    //TODO: add input size
    type Instance = LcsInstance<F, C, 5>;

    type Proof = ();

    type Error = ();

    fn transcript_pattern(builder: TranscriptBuilder<F>) -> TranscriptBuilder<F> {
        todo!()
    }

    fn prove(instance: Self::Instance) -> Self::Proof {
        todo!()
    }

    fn verify<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::Instance>,
        tanscript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
