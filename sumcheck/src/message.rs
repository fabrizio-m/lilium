use crate::{
    barycentric_eval::BarycentricWeights,
    polynomials::Evals,
    sumcheck::{Env, Var},
};
use ark_ff::Field;
use std::{
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, Sub},
};

pub struct Message<F: Field>(Vec<F>);

impl<F: Field> Message<F> {
    /// creates a degree 0 message
    // fn new_degree_0(eval: F) -> Self {
    // Self(vec![eval])
    // }
    pub(crate) fn new_degree_n(eval_at_0: F, eval_at_1: F, degree: usize) -> Self {
        assert!(degree >= 1, "degree should be >= 0");
        // e0, e1
        // P(x) = (e1 - e0)x + e0
        // TODO: it may be posible to exploit this structure further
        let mut message = Vec::with_capacity(degree);
        let diff = eval_at_1 - eval_at_0;
        let mut last = F::zero();
        //as x is 0..d multiplication is unnecessary
        for _ in 0..=degree {
            message.push(last + eval_at_0);
            last = last + diff;
        }
        Message(message)
    }
}

impl<F: Field> Message<F> {
    fn bin_op<B: Fn(F, F) -> F>(mut self, rhs: &Self, f: B) -> Self {
        for ab in self.0.iter_mut().zip(rhs.0.iter()) {
            let (a, b): (&mut F, &F) = ab;
            *a = f(*a, *b);
        }
        self
    }
    pub fn eval_at_0(&self) -> F {
        self.0[0]
    }
    pub fn eval_at_1(&self) -> F {
        self.0[1]
    }
    pub fn eval_at_x(&self, x: F, weights: &BarycentricWeights<F>) -> F {
        weights.evaluate(&self.0, x)
    }
}

impl<F: Field> Add<Self> for Message<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.bin_op(&rhs, |a: F, b: F| a + b)
    }
}
impl<F: Field> Sub<Self> for Message<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.bin_op(&rhs, |a: F, b: F| a - b)
    }
}
impl<F: Field> Mul<Self> for Message<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.bin_op(&rhs, |a: F, b: F| a * b)
    }
}
impl<F: Field> Add<&Self> for Message<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs, |a: F, b: F| a + b)
    }
}
impl<F: Field> Sub<&Self> for Message<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs, |a: F, b: F| a - b)
    }
}
impl<F: Field> Mul<&Self> for Message<F> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs, |a: F, b: F| a * b)
    }
}
impl<F: Field> Var for Message<F> {}
impl<F: Field> AddAssign for Message<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = rhs + &*self;
    }
}
pub struct MessageEnv<'a, I: Copy, F: Field, E: Evals<F, Idx = I>> {
    evals_left: &'a E,
    evals_right: &'a E,
    degree: usize,
    _phantom: PhantomData<(I, F)>,
}

impl<'a, I: Copy, F: Field, E: Evals<F, Idx = I>> MessageEnv<'a, I, F, E> {
    pub fn new(evals_left: &'a E, evals_right: &'a E, degree: usize) -> Self {
        Self {
            evals_left,
            evals_right,
            degree,
            _phantom: PhantomData,
        }
    }
}

impl<'a, I: Copy, F: Field, E: Evals<F, Idx = I>> Env<Message<F>, I> for MessageEnv<'a, I, F, E> {
    fn get(&self, i: I) -> Message<F> {
        let e0 = self.evals_left[i];
        let e1 = self.evals_right[i];
        let message = Message::new_degree_n(e0, e1, self.degree);
        message
    }
}
