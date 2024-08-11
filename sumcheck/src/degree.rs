//! An environment to measure degree of functions

use ark_ff::Field;

use crate::sumcheck::{Env, Var};
use std::{
    cmp::max,
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

#[derive(Clone, Copy)]
pub(crate) struct Degree(pub usize);

impl Add for Degree {
    type Output = Degree;

    fn add(self, rhs: Self) -> Self::Output {
        let Degree(a) = self;
        let Degree(b) = rhs;
        Degree(max(a, b))
    }
}
impl Add<&Self> for Degree {
    type Output = Degree;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}
impl Sub for Degree {
    type Output = Degree;

    fn sub(self, rhs: Self) -> Self::Output {
        let Degree(a) = self;
        let Degree(b) = rhs;
        Degree(max(a, b))
    }
}
impl Sub<&Self> for Degree {
    type Output = Degree;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}
impl Mul for Degree {
    type Output = Degree;

    fn mul(self, rhs: Self) -> Self::Output {
        let Degree(a) = self;
        let Degree(b) = rhs;
        Degree(a + b)
    }
}
impl Mul<&Self> for Degree {
    type Output = Degree;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl<F: Field> Var<F> for Degree {}

pub(crate) struct DegreeEnv<I>(PhantomData<I>);

impl<I> DegreeEnv<I> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<F: Field, I> Env<F, Degree, I> for DegreeEnv<I> {
    fn get(&self, _i: I) -> Degree {
        // TODO: this assumes every polynomial to be multilinear
        // which for now should be true in every case
        Degree(1)
    }
}
