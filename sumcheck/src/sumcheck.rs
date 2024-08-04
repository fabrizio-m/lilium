use std::{
    marker::PhantomData,
    ops::{Add, Index, Mul, Sub},
};

use ark_ff::Field;
use message::{Message, MessageEnv};

use crate::barycentric_eval::BarycentricWeights;

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

/// must be some wrapper over [F], representing all the evaluations at some
/// point of the domain
pub trait Evals<F: Field>: Index<Self::Idx, Output = F> {
    type Idx: Copy;
    ///should combine 2 [Self] into one by using `f` to combine each element
    fn combine<C: Fn(F, F) -> F>(&mut self, other: &Self, f: C) -> Self;
}

/// Defines a polynomial used in sumcheck as a function of multilinear
/// polynomials
pub trait SumcheckFunction<F: Field> {
    type Idx: Copy;
    type Mles: Evals<F, Idx = Self::Idx>;

    ///computes the arbitrary degree polynomial as a function of multilinear polynomials
    fn function<V: Var, E: Env<V, Self::Idx>>(env: E) -> V;
}

mod message {
    use crate::barycentric_eval::BarycentricWeights;

    use super::{Env, Evals, Var};
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
    // fn prove(&self, evals: Vec<SF::Mles>) {
    // }
    fn fix_var(mut mle: Vec<SF::Mles>, var: F) -> Vec<SF::Mles> {
        let half_len = mle.len() / 2;
        let one_minus_var = F::one() - var;
        let (left, right) = mle.split_at_mut(half_len);
        type Eval<F, SF> = <SF as SumcheckFunction<F>>::Mles;

        let f = |a, b| one_minus_var * a + var * b;
        for (left, right) in left.iter_mut().zip(right) {
            let left: &mut Eval<F, SF> = left;
            left.combine(right, f);
        }
        mle.truncate(half_len);
        mle
    }
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
    pub fn prove(&self, mle: Vec<SF::Mles>) -> Proof<F, SF> {
        //TODO: use schwartz-zippel
        let mut point = vec![F::one(); self.vars];
        let mut messages = Vec::with_capacity(self.vars);

        let _ = (0..self.vars).fold(mle, |mle, _| {
            let m = Self::message(&mle);
            messages.push(m);
            let var = point.pop().unwrap();
            Self::fix_var(mle, var)
        });
        Proof {
            messages,
            _f: PhantomData,
        }
    }
    //TODO: use multipoint
    // pub fn verify(&self, proof: Proof<F, SF>, sum: F) -> Result<F, ()> {}
}

pub struct SumcheckVerifier<F: Field, SF: SumcheckFunction<F>> {
    vars: usize,
    weights: BarycentricWeights<F>,
    _f: PhantomData<SF>,
}

impl<F: Field, SF: SumcheckFunction<F>> SumcheckVerifier<F, SF> {
    fn degree() -> u32 {
        todo!()
    }
    pub fn new(vars: usize) -> Self {
        let degree = Self::degree();
        let weights = BarycentricWeights::compute(degree);
        Self {
            vars,
            weights,
            _f: PhantomData,
        }
    }
    // TODO: use multipoint
    /// Verifies sumcheck, leaving it up to the caller to evaluate the polynomial
    /// in the point r and check that c = P(r) for Ok(c) the return value
    pub fn verify(&self, proof: Proof<F, SF>, sum: F) -> Result<F, ()> {
        let Proof { messages, _f } = proof;
        let mut point = vec![F::one(); self.vars];
        let mut sum = sum;
        for message in messages {
            let e0 = message.eval_at_0();
            let e1 = message.eval_at_1();
            if e0 + e1 != sum {
                return Err(());
            }
            let var = point.pop().unwrap();
            sum = message.eval_at_x(var, &self.weights);
        }
        let check_eval = sum;
        Ok(check_eval)
    }
}
