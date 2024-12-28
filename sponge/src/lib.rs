use ark_ff::Field;
pub mod constants_generation;
mod grain;

pub trait Sponge<F: Field> {
    fn new() -> Self;
    fn absorb(&mut self, val: F);
    fn squeeze(&mut self) -> F;
}
