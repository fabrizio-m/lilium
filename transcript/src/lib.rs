//! transcript implementation.

use ark_ff::Field;
pub mod protocols;
use params::ParamResolver;
pub use transcript::*;
pub use transcript_builder::*;

pub mod instances;
pub mod messages;
pub mod params;
mod transcript;
mod transcript_builder;
pub mod utils;

pub trait Message<F: Field> {
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize;
    fn to_field_elements(&self) -> Vec<F>;
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    SpongeError(sponge::Error),
    /// Attempt to send a message when no more messages were expected
    TranscriptFinished,
    /// Unexpected message or number of challenges generated
    UnexpectedMessage,
}
