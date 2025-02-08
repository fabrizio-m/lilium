use ark_ff::Field;

pub trait Permutation<F: Field, const T: usize> {
    fn new() -> Self;
    fn permute_mut(&self, state: &mut [F; T]);
}

/// Field generic, non-cryptographic permutation for testing
/// purposes.
pub struct UnsafePermutation<F: Field, const T: usize>([F; T]);

impl<F: Field, const T: usize> Permutation<F, T> for UnsafePermutation<F, T> {
    fn new() -> Self {
        let mut power = F::one() + F::one();
        let mut next = || {
            power += F::one();
            power.square_in_place();
            power
        };
        let constants = [(); T].map(|_| next());
        Self(constants)
    }

    fn permute_mut(&self, state: &mut [F; T]) {
        let sum: F = state.iter().sum();
        for _ in 0..4 {
            for i in 0..T {
                state[i] += self.0[i];
                state[i].square_in_place();
                state[i] *= self.0[i];
                state[i] += sum;
                let square = state[i].square();
                state[i] *= square;
            }
        }
    }
}
