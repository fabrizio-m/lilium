pub mod constants_generation;
mod grain;
pub mod permutation;
pub mod poseidon2;
pub mod sponge;

pub enum Error {
    /// attempted to squeeze an element before any previous absorb
    SqueezeBeforeAbsorb,
    /// attempted to squeeze or abosorb more elements than expected
    PatternOutOfBound,
    /// attempt to absorb when squeeze was expected
    UnexpectedAbsorb,
    /// attempt to squeeze when absorb was expected
    UnexpectedSqueeze,
}
