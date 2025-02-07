//! transcript implementation.

use ark_ff::Field;
pub mod protocols;
pub use transcript::*;
pub use transcript_builder::*;

pub mod instances;
mod transcript;
mod transcript_builder;

pub trait Message<F: Field> {
    fn len(vars: usize, degree: usize) -> usize;
    fn to_field_elements(&self) -> Vec<F>;
}

impl<F: Field> Message<F> for () {
    fn len(_vars: usize, _degree: usize) -> usize {
        0
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![]
    }
}

/// special type to generate points
struct PointRound;

impl<F: Field> Message<F> for PointRound {
    fn len(_vars: usize, _degree: usize) -> usize {
        0
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![]
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    SpongeError(sponge::Error),
    /// Attempt to send a message when no more messages were expected
    TranscriptFinished,
    /// Unexpected message or number of challenges generated
    UnexpectedMessage,
}
