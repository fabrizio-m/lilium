use crate::{flcs::FoldableLcsInstance, instances::lcs::LcsInstance};
use ark_ff::Field;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use sumcheck::zerocheck::CompactPowers;
use transcript::{
    protocols::Reduction, MessageGuard, Transcript, TranscriptBuilder, TranscriptGuard,
};

/// Reduction from LCS instances to foldable LCS instances, which
/// amounts to sampling a challenge to reduce zerocheck to sumcheck.
pub struct ZerocheckReduction<C, const I: usize>(PhantomData<C>);

/// The key amounts to just the number of variables involved in the
/// zerocheck, as one power of the challenge will be computed for each.
pub struct ZerocheckReductionKey(usize);

impl<F, C, const I: usize> Reduction<F> for ZerocheckReduction<C, I>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = LcsInstance<F, C, I>;

    type B = FoldableLcsInstance<F, C, I>;

    type Key = ZerocheckReductionKey;

    type Proof = ();

    type Error = transcript::Error;

    fn transcript_pattern(_key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder.round::<F, LcsInstance<F, C, I>, 1>()
    }

    fn verify_reduction<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [chall]) = transcript.unwrap_guard(instance)?;
        let LcsInstance {
            witness_commit,
            public_inputs,
        } = instance;
        let powers = CompactPowers::new(chall, key.0);
        Ok(FoldableLcsInstance::new(
            witness_commit,
            public_inputs,
            powers,
        ))
    }
}

impl ZerocheckReductionKey {
    pub fn new(vars: usize) -> Self {
        Self(vars)
    }

    pub(crate) fn reduce<F, C, S, const I: usize>(
        &self,
        instance: LcsInstance<F, C, I>,
        transcript: &mut Transcript<F, S>,
    ) -> FoldableLcsInstance<F, C, I>
    where
        F: Field,
        S: Duplex<F>,
        C: CommmitmentScheme<F> + 'static,
    {
        let [chall] = transcript.send_message(&instance).unwrap();
        let powers = CompactPowers::new(chall, self.0);
        let LcsInstance {
            witness_commit,
            public_inputs,
        } = instance;
        FoldableLcsInstance::new(witness_commit, public_inputs, powers)
    }
}
