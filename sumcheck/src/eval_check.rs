//! An environment to check the function of evaluations in a point.
//! At the end of sumcheck G(x) has to be check at a point r, as
//! G is but a composition of several multilinear polynomials, we instead
//! evaluates each of those polynomials at r and then apply the function
//! to get the evaluation. For example:
//! G(r) = f_0(r) * f_1(r) + f_2(r)

use crate::{
    polynomials::Evals,
    sumcheck::{Env, Var},
};
use ark_ff::Field;
use std::marker::PhantomData;

impl<F: Field> Var<F> for F {}
pub struct EvalCheckEnv<F: Field, I, E: Evals<F, Idx = I>> {
    evals: E,
    _phantom: PhantomData<(F, I)>,
}

impl<F: Field, I, E: Evals<F, Idx = I>> EvalCheckEnv<F, I, E> {
    pub fn new(eval: E) -> Self {
        Self {
            evals: eval,
            _phantom: PhantomData,
        }
    }
}

impl<F, I, E> Env<F, F, I> for EvalCheckEnv<F, I, E>
where
    F: Field,
    E: Evals<F, Idx = I>,
{
    fn get(&self, i: I) -> F {
        let f = self.evals[i];
        f
    }
}
