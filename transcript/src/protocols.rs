use crate::{
    transcript::{MessageGuard, TranscriptGuard},
    Message, TranscriptBuilder,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::fmt::Debug;

pub trait Protocol<F: Field> {
    type Key;
    type Instance: Message<F>;
    type Proof;
    type Error: Debug + Clone;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder;
    fn prove(instance: Self::Instance) -> Self::Proof;
    fn verify<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::Instance>,
        transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<(), Self::Error>;
}

pub trait Reduction<F: Field> {
    type A: Message<F>;
    type B;
    type Key;
    type Proof;
    type Error;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder;
    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error>;
}
