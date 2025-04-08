use crate::sumcheck::{Env, Var};
use crate::symbolic::compute::MvPoly;
use ark_ff::Field;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub};

#[derive(Debug, Clone)]
pub(crate) enum Expression<F, V, C> {
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Var(V),
    Challenge(C),
    Const(F),
}

impl<F, V, C> Expression<F, V, C> {
    fn bin_op<O>(self, other: Self, f: O) -> Self
    where
        O: Fn(Box<Self>, Box<Self>) -> Self,
    {
        f(Box::new(self), Box::new(other))
    }
}

impl<F: Field, V: Clone, C: Clone> Var<F> for Expression<F, V, C> {}

impl<F: Field, V, C> Add for Expression<F, V, C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.bin_op(rhs, Expression::Add)
    }
}

impl<F: Field, V: Clone, C: Clone> Add<&Self> for Expression<F, V, C> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs.clone(), Expression::Add)
    }
}

impl<F: Field, V, C> Sub for Expression<F, V, C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.bin_op(rhs, Expression::Sub)
    }
}

impl<F: Field, V: Clone, C: Clone> Sub<&Self> for Expression<F, V, C> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs.clone(), Expression::Sub)
    }
}

impl<F: Field, V, C> Mul for Expression<F, V, C> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.bin_op(rhs, Expression::Mul)
    }
}

impl<F: Field, V: Clone, C: Clone> Mul<&Self> for Expression<F, V, C> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs.clone(), Expression::Mul)
    }
}

impl<F: Field, V, C> Add<F> for Expression<F, V, C> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        let rhs = Expression::Const(rhs);
        self.bin_op(rhs, Expression::Add)
    }
}

impl<F: Field, V, C> Sub<F> for Expression<F, V, C> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        let rhs = Expression::Const(rhs);
        self.bin_op(rhs, Expression::Sub)
    }
}

impl<F: Field, V, C> Mul<F> for Expression<F, V, C> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        let rhs = Expression::Const(rhs);
        self.bin_op(rhs, Expression::Mul)
    }
}

impl<F: Field, V: Clone, C: Clone> AddAssign<&Self> for Expression<F, V, C> {
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.clone() + rhs;
    }
}

impl<F: Field, V: Clone, C: Clone> MulAssign<F> for Expression<F, V, C> {
    fn mul_assign(&mut self, rhs: F) {
        *self = self.clone() * rhs;
    }
}

pub(crate) struct ExpEnv;

impl<F, V, C> Env<F, Expression<F, V, C>, V, C> for ExpEnv
where
    F: Field,
    V: Clone,
    C: Clone,
{
    fn get(&self, i: V) -> Expression<F, V, C> {
        Expression::Var(i)
    }
    fn get_chall(&self, chall_idx: C) -> Expression<F, V, C> {
        Expression::Challenge(chall_idx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VarOrChall<V, C> {
    Var(V),
    Challenge(C),
}

/// Evaluates expression tree into a mv polynomial.
pub(crate) fn compute_mv_poly<F, V, C>(exp: Expression<F, V, C>) -> MvPoly<F, VarOrChall<V, C>>
where
    F: Field,
    V: Eq + Ord + Clone,
    C: Eq + Ord + Clone,
{
    use Expression::*;
    let f = compute_mv_poly;
    match exp {
        Add(e1, e2) => f(*e1) + f(*e2),
        Sub(e1, e2) => f(*e1) - f(*e2),
        Mul(e1, e2) => f(*e1) * f(*e2),
        Var(var) => MvPoly::new(VarOrChall::Var(var), F::one()),
        Const(c) => MvPoly::new_const(c),
        Challenge(c) => MvPoly::new(VarOrChall::Challenge(c), F::one()),
    }
}
