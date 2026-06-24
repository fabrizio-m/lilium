use crate::spark3::{
    reduction, sumcheck_argument::SparkEvals, FlexibleSparkRelation, FlexibleSparkStructure,
    SparkInstance, SparkReduction,
};
use ark_ff::Field;
use commit::commit2::{CommitmentScheme, OpenInstance, OpeningRelation};
use sponge::sponge::Duplex;
use transcript::reduction2::{
    GuardedProof, ProverOutput, Reduction, Transcript, TranscriptBuilder, VerifierTranscript,
};

/// Wrapper which dynamically chooses N as required, currently implemented up to
/// 64 bits/8 segments.
pub enum FlexibleSpark<F: Field, C: CommitmentScheme<F>> {
    S1(SparkReduction<F, C, 1>),
    S2(SparkReduction<F, C, 2>),
    S3(SparkReduction<F, C, 3>),
    S4(SparkReduction<F, C, 4>),
    S5(SparkReduction<F, C, 5>),
    S6(SparkReduction<F, C, 6>),
    S7(SparkReduction<F, C, 7>),
    S8(SparkReduction<F, C, 8>),
}

pub enum VerifierKey<F, C>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    S1(reduction::Key<F, C, SparkEvals<(), 1>, 1>),
    S2(reduction::Key<F, C, SparkEvals<(), 2>, 2>),
    S3(reduction::Key<F, C, SparkEvals<(), 3>, 3>),
    S4(reduction::Key<F, C, SparkEvals<(), 4>, 4>),
    S5(reduction::Key<F, C, SparkEvals<(), 5>, 5>),
    S6(reduction::Key<F, C, SparkEvals<(), 6>, 6>),
    S7(reduction::Key<F, C, SparkEvals<(), 7>, 7>),
    S8(reduction::Key<F, C, SparkEvals<(), 8>, 8>),
}

type Rel1<F> = FlexibleSparkRelation<F>;
type Rel2<F, C> = OpeningRelation<F, C>;

impl<F, C> Reduction<F, Rel1<F>, Rel2<F, C>> for FlexibleSpark<F, C>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    type ProverKey = ();

    type VerifierKey = VerifierKey<F, C>;

    type Proof = ();

    type Error = ();

    fn transcript_pattern(
        key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        use VerifierKey::*;
        match key {
            S1(key) => SparkReduction::transcript_pattern(key, builder),
            S2(key) => SparkReduction::transcript_pattern(key, builder),
            S3(key) => SparkReduction::transcript_pattern(key, builder),
            S4(key) => SparkReduction::transcript_pattern(key, builder),
            S5(key) => SparkReduction::transcript_pattern(key, builder),
            S6(key) => SparkReduction::transcript_pattern(key, builder),
            S7(key) => SparkReduction::transcript_pattern(key, builder),
            S8(key) => SparkReduction::transcript_pattern(key, builder),
        }
    }

    fn verifier_key(
        _structure_1: &FlexibleSparkStructure<F>,
        _structure_2: &C,
    ) -> Self::VerifierKey {
        todo!()
    }

    fn key_pair(
        _structure_1: &FlexibleSparkStructure<F>,
        _structure_2: &C,
    ) -> (Self::VerifierKey, Self::ProverKey) {
        todo!()
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: SparkInstance<F>,
        _: (),
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<Rel2<F, C>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        _key: &Self::VerifierKey,
        _instance: SparkInstance<F>,
        _proof: GuardedProof<Self::Proof>,
        _transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<OpenInstance<F, C>, Self::Error> {
        todo!()
    }
}
