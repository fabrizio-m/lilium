use crate::constraint_system::{ConstraintSystem, Gate, Var};
use ark_ff::Field;
use std::ops::{Add, Mul, Sub};

#[derive(Clone, Copy)]
pub struct Fi<F: Field>(F);

impl<F: Field> Add for Fi<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}
impl<F: Field> Sub for Fi<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}
impl<F: Field> Mul for Fi<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<F: Field> Var for Fi<F> {}

pub struct WitnessGenerator<F: Field, const IO: usize> {
    witness: Vec<Fi<F>>,
    check: bool,
}
pub struct Witness<F: Field>(pub Vec<F>);

impl<F: Field, const MAX_IO: usize> ConstraintSystem for WitnessGenerator<F, MAX_IO> {
    type V = Fi<F>;

    fn execute<G, const IO: usize, const I: usize, const O: usize>(
        &mut self,
        i: [Self::V; I],
    ) -> [Self::V; O]
    where
        G: Gate<IO, I, O> + 'static,
    {
        let out = G::gate(i);
        for o in out.iter() {
            self.witness.push(*o);
        }
        if self.check {
            let constraints = G::check(i, out);
            for constraint in constraints {
                if !constraint.0.is_zero() {
                    //it may be better to store all errors and report at the end instead of this
                    panic!("constraint evaluates to non zero");
                }
            }
        }
        out
    }
}

impl<F: Field, const MAX_IO: usize> WitnessGenerator<F, MAX_IO> {
    fn new(check: bool) -> Self {
        let witness = vec![Fi(F::one())];
        Self { witness, check }
    }
    // fn with_inputs(check:bool,)
    pub fn with_io<const I: usize, const O: usize>(
        check: bool,
        inputs: [F; I],
    ) -> (Self, [Fi<F>; I]) {
        let mut new = Self::new(check);
        let input = inputs.map(|x| Fi(x));
        new.witness.extend(input.iter().cloned());
        //just fill with some arbitrary element, will later be replaced
        new.witness.extend([Fi(F::zero()); O]);
        (new, input)
    }
    pub fn link_outputs<const I: usize, const O: usize>(&mut self, outputs: [Fi<F>; O]) {
        for i in 0..O {
            let b = outputs[i];
            let i = i + I + 1;
            self.witness[i] = b;
        }
    }
    pub fn witness(self) -> Witness<F> {
        Witness(self.witness.into_iter().map(|x| x.0).collect())
    }
}
pub fn unwrap_output<F: Field, const O: usize>(o: [Fi<F>; O]) -> [F; O] {
    o.map(|x| x.0)
}
