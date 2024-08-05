use crate::{
    barycentric_eval::BarycentricWeights,
    degree::DegreeEnv,
    eval_check::EvalCheckEnv,
    message::{Message, MessageEnv},
    polynomials::{Evals, EvalsExt, MultiPoint},
};
use ark_ff::Field;
use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

pub trait Var:
    Sized
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
// where
// for<'a> &'a Self: Add<&'a Self, Output = Self>,
// for<'a> &'a Self: Sub<&'a Self, Output = Self>,
// for<'a> &'a Self: Mul<&'a Self, Output = Self>,
{
}

///allows access to variables
pub trait Env<V, I>
where
    V: Var,
{
    fn get(&self, i: I) -> V;
}

/// Defines a polynomial used in sumcheck as a function of multilinear
/// polynomials
pub trait SumcheckFunction<F: Field> {
    type Idx: Copy;
    type Mles: Evals<F, Idx = Self::Idx>;

    ///computes the arbitrary degree polynomial as a function of multilinear polynomials
    fn function<V: Var, E: Env<V, Self::Idx>>(env: E) -> V;
}

pub struct SumcheckProver<F: Field, SF: SumcheckFunction<F>> {
    _phantom: PhantomData<(F, SF)>,
    vars: usize,
}

pub struct Proof<F: Field, SF: SumcheckFunction<F>> {
    messages: Vec<Message<F>>,
    _f: PhantomData<SF>,
}

impl<F: Field, SF: SumcheckFunction<F>> SumcheckProver<F, SF> {
    fn message(mle: &[SF::Mles]) -> Message<F> {
        let half_len = mle.len() / 2;
        let (left, right) = mle.split_at(half_len);
        let degree = 8;

        let mut message = Message::new_degree_n(F::zero(), F::zero(), degree);
        for (left, right) in left.iter().zip(right) {
            // let left: &mut Eval<F, SF> = left;
            // left.combine(right, f);
            let env = MessageEnv::new(left, right, degree);
            let m = SF::function(env);
            message += m;
        }
        message
    }
    pub fn prove(&self, r: MultiPoint<F>, mle: Vec<SF::Mles>) -> Proof<F, SF> {
        assert_eq!(self.vars, r.vars());
        let point = r;
        let mut messages = Vec::with_capacity(self.vars);

        let _ = (0..self.vars).fold((mle, point), |(mle, point), _| {
            let m = Self::message(&mle);
            messages.push(m);
            let (point, var) = point.pop();
            (EvalsExt::fix_var(mle, var), point)
        });
        Proof {
            messages,
            _f: PhantomData,
        }
    }
}

pub struct SumcheckVerifier<F: Field, SF: SumcheckFunction<F>> {
    vars: usize,
    weights: BarycentricWeights<F>,
    degree: usize,
    _f: PhantomData<SF>,
}

impl<F: Field, SF: SumcheckFunction<F>> SumcheckVerifier<F, SF> {
    fn degree() -> u32 {
        todo!()
    }
    pub fn new(vars: usize) -> Self {
        let degree = Self::degree();
        let weights = BarycentricWeights::compute(degree);
        let degree_env = DegreeEnv::new();
        let degree = SF::function(degree_env).0;
        Self {
            vars,
            weights,
            degree,
            _f: PhantomData,
        }
    }
    // TODO: use multipoint
    /// Verifies sumcheck, leaving it up to the caller to evaluate the polynomial
    /// in the point r and check that c = P(r) for Ok(c) the return value
    pub fn verify(&self, r: MultiPoint<F>, proof: Proof<F, SF>, sum: F) -> Result<F, ()> {
        assert_eq!(self.vars, r.vars());
        let Proof { messages, _f } = proof;
        // let mut point = vec![F::one(); self.vars];
        let mut point = r;
        let mut sum = sum;
        for message in messages {
            if message.degree() != self.degree {
                return Err(());
            }
            let e0 = message.eval_at_0();
            let e1 = message.eval_at_1();
            if e0 + e1 != sum {
                return Err(());
            }
            let var = point.pop_mut();
            sum = message.eval_at_x(var, &self.weights);
        }
        let check_eval = sum;
        Ok(check_eval)
    }
    // Will check that c = P(r) from the evaluations of the
    // multilinear polynomials that compose it
    pub fn check_evals_at_r(&self, evals: SF::Mles, c: F) -> bool {
        let env = EvalCheckEnv::new(evals);
        let eval = SF::function(env);
        eval == c
    }
}
