use ark_ff::Field;

pub trait Permutation<F: Field, const T: usize> {
    fn new() -> Self;
    fn permute_mut(&self, state: &mut [F; T]);
}
