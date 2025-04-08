use crate::sumcheck::{Env, Var};
use crate::symbolic::compute::MvPoly;
use ark_ff::Field;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub};

#[derive(Debug, Clone)]
pub(crate) enum Expression<F, V> {
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Var(V),
    Const(F),
}

impl<F, V> Expression<F, V> {
    fn bin_op<O>(self, other: Self, f: O) -> Self
    where
        O: Fn(Box<Self>, Box<Self>) -> Self,
    {
        f(Box::new(self), Box::new(other))
    }
}

impl<F: Field, V: Clone> Var<F> for Expression<F, V> {}

impl<F: Field, V> Add for Expression<F, V> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.bin_op(rhs, Expression::Add)
    }
}

impl<F: Field, V: Clone> Add<&Self> for Expression<F, V> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs.clone(), Expression::Add)
    }
}

impl<F: Field, V> Sub for Expression<F, V> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.bin_op(rhs, Expression::Sub)
    }
}

impl<F: Field, V: Clone> Sub<&Self> for Expression<F, V> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs.clone(), Expression::Sub)
    }
}

impl<F: Field, V> Mul for Expression<F, V> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.bin_op(rhs, Expression::Mul)
    }
}

impl<F: Field, V: Clone> Mul<&Self> for Expression<F, V> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs.clone(), Expression::Mul)
    }
}

impl<F: Field, V> Add<F> for Expression<F, V> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        let rhs = Expression::Const(rhs);
        self.bin_op(rhs, Expression::Add)
    }
}

impl<F: Field, V> Sub<F> for Expression<F, V> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        let rhs = Expression::Const(rhs);
        self.bin_op(rhs, Expression::Sub)
    }
}

impl<F: Field, V> Mul<F> for Expression<F, V> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        let rhs = Expression::Const(rhs);
        self.bin_op(rhs, Expression::Mul)
    }
}

impl<F: Field, V: Clone> AddAssign<&Self> for Expression<F, V> {
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.clone() + rhs;
    }
}

impl<F: Field, V: Clone> MulAssign<F> for Expression<F, V> {
    fn mul_assign(&mut self, rhs: F) {
        *self = self.clone() * rhs;
    }
}

pub(crate) struct ExpEnv;

impl<F: Field, V: Clone> Env<F, Expression<F, V>, V> for ExpEnv {
    fn get(&self, i: V) -> Expression<F, V> {
        Expression::Var(i)
    }
}

/// Evaluates expression tree into a mv polynomial.
pub(crate) fn compute_mv_poly<F, V>(exp: Expression<F, V>) -> MvPoly<F, V>
where
    F: Field,
    V: Eq + Ord + Clone,
{
    use Expression::*;
    let f = compute_mv_poly;
    match exp {
        Add(e1, e2) => f(*e1) + f(*e2),
        Sub(e1, e2) => f(*e1) - f(*e2),
        Mul(e1, e2) => f(*e1) * f(*e2),
        Var(var) => MvPoly::new(var, F::one()),
        Const(c) => MvPoly::new_const(c),
    }
}
