use crate::{
    committed_spark::{CommittedSparkInstance, Error},
    spark2::{CommittedSpark, CommittedSparkProof},
};
use ark_ff::Field;
use commit::{CommmitmentScheme, OpenInstance};
use sponge::sponge::Duplex;
use sumcheck::polynomials::MultiPoint;
use transcript::{
    params::ParamResolver, protocols::Reduction, Message, MessageGuard, TranscriptBuilder,
    TranscriptGuard,
};

/// Wrapper which dynamically chooses N as required, currently implemented up to
/// 64 bits/8 segments.
pub enum FlexibleSpark<F: Field, C: CommmitmentScheme<F>> {
    S1(CommittedSpark<F, C, 1>),
    S2(CommittedSpark<F, C, 2>),
    S3(CommittedSpark<F, C, 3>),
    S4(CommittedSpark<F, C, 4>),
    S5(CommittedSpark<F, C, 5>),
    S6(CommittedSpark<F, C, 6>),
    S7(CommittedSpark<F, C, 7>),
    S8(CommittedSpark<F, C, 8>),
}

pub struct Instance<F: Field> {
    /// One single big point for all segments
    pub point: MultiPoint<F>,
    pub eval: F,
}

impl<F: Field> Instance<F> {
    pub fn slice<const N: usize>(self) -> CommittedSparkInstance<F, N> {
        let Self { point, eval } = self;
        //TODO: this is enforcing by alignment, may want to remove.
        assert_eq!(point.vars(), N * 8);

        let mut vars = point.inner().into_iter();

        let point = [(); N].map(|_| {
            let vars: Vec<F> = vars.by_ref().take(8).collect();
            MultiPoint::new(vars)
        });

        CommittedSparkInstance { point, eval }
    }
}

/// How many 8-bits segments Spark is using.
struct SegmentsParam;

impl<F: Field> Message<F> for Instance<F> {
    fn len(_vars: usize, param_resolver: &ParamResolver) -> usize {
        //TODO: could use bits instead and compute segments from them.
        let segments = param_resolver.get::<SegmentsParam>();
        segments * 8 + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = Vec::with_capacity(self.point.vars() + 1);
        elems.extend(self.point.inner_ref());
        elems.push(self.eval);
        elems
    }
}

pub enum Proof<F: Field, C: CommmitmentScheme<F>> {
    S1(CommittedSparkProof<F, C, 1>),
    S2(CommittedSparkProof<F, C, 2>),
    S3(CommittedSparkProof<F, C, 3>),
    S4(CommittedSparkProof<F, C, 4>),
    S5(CommittedSparkProof<F, C, 5>),
    S6(CommittedSparkProof<F, C, 6>),
    S7(CommittedSparkProof<F, C, 7>),
    S8(CommittedSparkProof<F, C, 8>),
}

impl<F, C> Reduction<F> for FlexibleSpark<F, C>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = Instance<F>;

    type B = OpenInstance<F, C::Commitment>;

    type Key = Self;

    type Proof = Proof<F, C>;

    type Error = Error<F, C>;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        use FlexibleSpark::*;
        match key {
            S1(key) => CommittedSpark::transcript_pattern(key, builder),
            S2(key) => CommittedSpark::transcript_pattern(key, builder),
            S3(key) => CommittedSpark::transcript_pattern(key, builder),
            S4(key) => CommittedSpark::transcript_pattern(key, builder),
            S5(key) => CommittedSpark::transcript_pattern(key, builder),
            S6(key) => CommittedSpark::transcript_pattern(key, builder),
            S7(key) => CommittedSpark::transcript_pattern(key, builder),
            S8(key) => CommittedSpark::transcript_pattern(key, builder),
        }
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        use FlexibleSpark::*;
        //TODO:handle
        let (instance, []) = transcript.unwrap_guard(instance).unwrap();
        macro_rules! verify {
            ($variant:path,$key:ident) => {{
                let instance = MessageGuard::new(instance.slice());
                let proof = transcript.receive_message_delayed(|proof| {
                    if let $variant(proof) = proof {
                        proof.clone()
                    } else {
                        panic!()
                    }
                });
                let transcript = transcript.new_guard(proof);
                CommittedSpark::verify_reduction($key, instance, transcript)
            }};
        }
        match key {
            S1(key) => {
                verify!(Proof::S1, key)
            }
            S2(key) => {
                verify!(Proof::S2, key)
            }
            S3(key) => {
                verify!(Proof::S3, key)
            }
            S4(key) => {
                verify!(Proof::S4, key)
            }
            S5(key) => {
                verify!(Proof::S5, key)
            }
            S6(key) => {
                verify!(Proof::S6, key)
            }
            S7(key) => {
                verify!(Proof::S7, key)
            }
            S8(key) => {
                verify!(Proof::S8, key)
            }
        }
    }
}
