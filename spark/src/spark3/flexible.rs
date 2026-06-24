use crate::spark3::{
    prove,
    reduction::{self, SparkError},
    sumcheck_argument::SparkEvals,
    FlexibleSparkRelation, FlexibleSparkStructure, SparkInstance, SparkReduction,
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

pub enum ProverKey<F, C>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    S1(prove::ProverKey<F, C, 1>),
    S2(prove::ProverKey<F, C, 2>),
    S3(prove::ProverKey<F, C, 3>),
    S4(prove::ProverKey<F, C, 4>),
    S5(prove::ProverKey<F, C, 5>),
    S6(prove::ProverKey<F, C, 6>),
    S7(prove::ProverKey<F, C, 7>),
    S8(prove::ProverKey<F, C, 8>),
}

#[derive(Clone, Debug)]
pub enum Proof<F: Field, C: CommitmentScheme<F>> {
    S1(reduction::Proof<F, C, 1>),
    S2(reduction::Proof<F, C, 2>),
    S3(reduction::Proof<F, C, 3>),
    S4(reduction::Proof<F, C, 4>),
    S5(reduction::Proof<F, C, 5>),
    S6(reduction::Proof<F, C, 6>),
    S7(reduction::Proof<F, C, 7>),
    S8(reduction::Proof<F, C, 8>),
}

type Rel1<F> = FlexibleSparkRelation<F>;
type Rel2<F, C> = OpeningRelation<F, C>;

#[derive(Clone, Copy, Debug)]
pub enum FlexibleSparkError {
    UnexpectedProofSize,
    Spark(SparkError),
}

impl<F, C> Reduction<F, Rel1<F>, Rel2<F, C>> for FlexibleSpark<F, C>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    type ProverKey = ProverKey<F, C>;

    type VerifierKey = VerifierKey<F, C>;

    type Proof = Proof<F, C>;

    type Error = FlexibleSparkError;

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
        key: &Self::ProverKey,
        instance: SparkInstance<F>,
        _: (),
        transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<Rel2<F, C>, Self::Proof> {
        macro_rules! prove {
            ($variant:path,$key:ident) => {{
                let ProverOutput {
                    instance,
                    witness,
                    proof,
                } = SparkReduction::prove($key, instance, (), transcript);
                let proof = $variant(proof);
                ProverOutput {
                    instance,
                    witness,
                    proof,
                }
            }};
        }

        match key {
            ProverKey::S1(key) => {
                prove!(Proof::S1, key)
            }
            ProverKey::S2(key) => {
                prove!(Proof::S2, key)
            }
            ProverKey::S3(key) => {
                prove!(Proof::S3, key)
            }
            ProverKey::S4(key) => {
                prove!(Proof::S4, key)
            }
            ProverKey::S5(key) => {
                prove!(Proof::S5, key)
            }
            ProverKey::S6(key) => {
                prove!(Proof::S6, key)
            }
            ProverKey::S7(key) => {
                prove!(Proof::S7, key)
            }
            ProverKey::S8(key) => {
                prove!(Proof::S8, key)
            }
        }
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: SparkInstance<F>,
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<OpenInstance<F, C>, Self::Error> {
        use VerifierKey::*;

        macro_rules! verify {
            ($variant:path,$key:ident) => {{
                let proof = proof.try_map(|proof| {
                    if let $variant(proof) = proof {
                        Some(proof)
                    } else {
                        None
                    }
                });
                let proof = proof.map_err(|_| FlexibleSparkError::UnexpectedProofSize)?;
                let res = SparkReduction::verify($key, instance, proof, transcript);
                res.map_err(FlexibleSparkError::Spark)
            }};
        }

        match key {
            S1(key) => verify!(Proof::S1, key),
            S2(key) => verify!(Proof::S2, key),
            S3(key) => verify!(Proof::S3, key),
            S4(key) => verify!(Proof::S4, key),
            S5(key) => verify!(Proof::S5, key),
            S6(key) => verify!(Proof::S6, key),
            S7(key) => verify!(Proof::S7, key),
            S8(key) => verify!(Proof::S8, key),
        }
    }
}
