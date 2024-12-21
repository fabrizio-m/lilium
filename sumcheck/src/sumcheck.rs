use crate::{
    barycentric_eval::BarycentricWeights,
    degree::DegreeEnv,
    eval_check::EvalCheckEnv,
    message::{Message, MessageEnv},
    polynomials::{Evals, EvalsExt, MultiPoint},
    SumcheckError,
};
use ark_ff::Field;
use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign, Sub},
};

pub trait Var<F: Field>:
    Sized
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + Add<F, Output = Self>
    + Sub<F, Output = Self>
    + Mul<F, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + MulAssign<F>
    + Clone
{
}

/// allows access to variables
pub trait Env<F, V, I>
where
    F: Field,
    V: Var<F>,
{
    fn get(&self, i: I) -> V;
}
// implement also for references
impl<F: Field, V: Var<F>, I, E: Env<F, V, I>> Env<F, V, I> for &E {
    fn get(&self, i: I) -> V {
        (*self).get(i)
    }
}

#[derive(Clone, Copy, Debug)]
/// Describes how a given mle should be evaluated at a point
pub enum EvalKind {
    /// To be evaluated through opening a commitment
    Committed,
    /// Small representation that can be just evaluated by the verifier
    FixedSmall,
    /// Some MLE that can't be directly evaluated, the evaluation is
    /// provided as a claim to be verified later through other means.
    /// The specific use of this is for matrix evalation with spark.
    Virtual,
}

/// Defines a polynomial used in sumcheck as a function of multilinear
/// polynomials
pub trait SumcheckFunction<F: Field> {
    type Idx: Copy;
    type Mles<V: Copy + Debug>: Evals<V, Idx = Self::Idx>;
    type Challs: Default;

    /// Provides a description of how each mle should be evaluated
    fn eval_kinds() -> Self::Mles<EvalKind>;
    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B;
    ///computes the arbitrary degree polynomial as a function of multilinear polynomials
    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E, challs: &Self::Challs) -> V;
}

pub struct SumcheckProver<F: Field, SF: SumcheckFunction<F>> {
    _phantom: PhantomData<(F, SF)>,
    vars: usize,
    degree: usize,
}

#[derive(Clone, Debug)]
pub struct Proof<F: Field, SF: SumcheckFunction<F>> {
    messages: Vec<Message<F>>,
    _f: PhantomData<SF>,
}

impl<F, SF> SumcheckProver<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    pub fn new(vars: usize) -> Self {
        let degree = Self::degree();
        Self {
            _phantom: PhantomData,
            degree,
            vars,
        }
    }
    fn degree() -> usize {
        let degree_env = DegreeEnv::new();
        let challs = <SF::Challs as Default>::default();
        let degree = SF::function(degree_env, &challs);
        degree.0
    }
    fn message(&self, mle: &[SF::Mles<F>], challs: &SF::Challs) -> Message<F> {
        let half_len = mle.len() / 2;
        let (left, right) = mle.split_at(half_len);
        let degree = self.degree;

        let mut message = Message::new_degree_n(F::zero(), F::zero(), degree);
        for (left, right) in left.iter().zip(right) {
            // let left: &mut Eval<F, SF> = left;
            // left.combine(right, f);
            let env = MessageEnv::new(left, right, degree);
            let m = SF::function(env, challs);
            message += m;
        }
        message
    }
    pub fn prove(
        &self,
        r: &MultiPoint<F>,
        mle: Vec<SF::Mles<F>>,
        challs: &SF::Challs,
    ) -> Proof<F, SF> {
        assert_eq!(self.vars, r.vars());
        let point = r.clone();
        let mut messages = Vec::with_capacity(self.vars);

        let _ = (0..self.vars).fold((mle, point), |(mle, point), _| {
            let m = self.message(&mle, challs);
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
        let degree_env = DegreeEnv::new();
        let challs = <SF::Challs as Default>::default();
        let degree = SF::function(degree_env, &challs);
        degree.0 as u32
    }
    pub fn new(vars: usize) -> Self {
        let degree = Self::degree();
        let weights = BarycentricWeights::compute(degree);
        let degree = degree as usize;
        Self {
            vars,
            weights,
            degree,
            _f: PhantomData,
        }
    }
    /// Verifies sumcheck, leaving it up to the caller to evaluate the polynomial
    /// in the point r and check that c = P(r) for Ok(c) the return value
    pub fn verify(
        &self,
        r: &MultiPoint<F>,
        proof: Proof<F, SF>,
        sum: F,
    ) -> Result<F, SumcheckError> {
        assert_eq!(self.vars, r.vars());
        let Proof { messages, _f } = proof;
        let mut point = r.clone();
        let mut sum = sum;
        for message in messages {
            if message.degree() != self.degree {
                return Err(SumcheckError::MessageDegree);
            }
            let e0 = message.eval_at_0();
            let e1 = message.eval_at_1();

            if e0 + e1 != sum {
                return Err(SumcheckError::RoundSum);
            }
            let var = point.pop_mut();
            sum = message.eval_at_x(var, &self.weights);
        }
        let check_eval = sum;
        Ok(check_eval)
    }
    // Will check that c = P(r) from the evaluations of the
    // multilinear polynomials that compose it
    pub fn check_evals_at_r(&self, evals: SF::Mles<F>, c: F, challs: &SF::Challs) -> bool {
        let env = EvalCheckEnv::new(evals);
        let eval = SF::function(env, challs);
        eval == c
    }
}

#[cfg(test)]
mod test {
    use crate::{
        polynomials::{Evals, EvalsExt, MultiPoint},
        sumcheck::{Env, SumcheckFunction, SumcheckProver, SumcheckVerifier, Var},
    };
    use ark_vesta::Fr;
    use rand::{thread_rng, Rng};
    use std::fmt::Debug;

    use super::EvalKind;

    #[derive(Clone, Copy)]
    struct Eval<V = Fr> {
        a: V,
        b: V,
        c: V,
    }

    impl<V: Copy> Evals<V> for Eval<V> {
        type Idx = usize;

        fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
            let a = f(self.a, other.a);
            let b = f(self.b, other.b);
            let c = f(self.c, other.c);
            Eval { a, b, c }
        }

        fn index(&self, index: Self::Idx) -> &V {
            match index {
                0 => &self.a,
                1 => &self.b,
                2 => &self.c,
                _ => {
                    unreachable!()
                }
            }
        }

        fn flatten(self, vec: &mut Vec<V>) {
            let Self { a, b, c } = self;
            vec.push(a);
            vec.push(b);
            vec.push(c);
        }

        fn unflatten(vec: &mut Vec<V>) -> Self {
            let c = vec.pop().unwrap();
            let b = vec.pop().unwrap();
            let a = vec.pop().unwrap();
            Self { a, b, c }
        }
    }

    fn map_evals<A, B, M>(evals: Eval<A>, f: M) -> Eval<B>
    where
        A: Copy,
        B: Copy,
        M: Fn(A) -> B,
    {
        let Eval { a, b, c } = evals;
        let a = f(a);
        let b = f(b);
        let c = f(c);
        Eval { a, b, c }
    }
    struct MulGate;
    impl SumcheckFunction<Fr> for MulGate {
        type Idx = usize;
        type Mles<V: Copy + Debug> = Eval<V>;
        type Challs = ();

        fn function<V: Var<Fr>, E: Env<Fr, V, Self::Idx>>(env: E, _challs: &()) -> V {
            let a = env.get(0);
            let b = env.get(1);
            let c = env.get(2);
            (a.clone() * b) - c
        }

        fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
        where
            A: Copy + Debug,
            B: Copy + Debug,
            M: Fn(A) -> B,
        {
            map_evals(evals, f)
        }

        fn eval_kinds() -> Self::Mles<EvalKind> {
            Eval {
                a: EvalKind::FixedSmall,
                b: EvalKind::FixedSmall,
                c: EvalKind::FixedSmall,
            }
        }
    }
    struct SquareGate;
    impl SumcheckFunction<Fr> for SquareGate {
        type Idx = usize;
        type Mles<V: Copy + Debug> = Eval<V>;
        type Challs = ();

        fn function<V: Var<Fr>, E: Env<Fr, V, Self::Idx>>(env: E, _challs: &()) -> V {
            let a = env.get(0);
            a.clone() * a
        }

        fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
        where
            A: Copy + Debug,
            B: Copy + Debug,
            M: Fn(A) -> B,
        {
            map_evals(evals, f)
        }
        fn eval_kinds() -> Self::Mles<EvalKind> {
            Eval {
                a: EvalKind::FixedSmall,
                b: EvalKind::FixedSmall,
                c: EvalKind::FixedSmall,
            }
        }
    }

    #[test]
    fn sumcheck_mul() {
        let vars = 8;
        let domain_size = 1 << vars;
        let prover = SumcheckProver::<Fr, MulGate>::new(vars);
        let verifier = SumcheckVerifier::new(vars);
        let mut rng = thread_rng();
        let mut rand_fr = || rng.gen::<Fr>();
        let mut rand_eval = || {
            let a = rand_fr();
            let b = rand_fr();
            let c = a * b;
            Eval { a, b, c }
        };
        let mle: Vec<Eval> = (0..domain_size).map(|_| rand_eval()).collect();

        //this should depend on mle in a real case
        let r = vec![rand_fr(); vars];
        let r = MultiPoint::new(r);

        let proof = prover.prove(&r, mle.clone(), &());

        let sum = Fr::from(0);
        let c = verifier.verify(&r, proof, sum).unwrap();

        let evals = EvalsExt::eval(mle, r);
        let check = verifier.check_evals_at_r(evals, c, &());
        assert!(check);
    }
    #[test]
    fn sumcheck_square() {
        let vars = 3;
        let domain_size = 1 << vars;
        let prover = SumcheckProver::<Fr, SquareGate>::new(vars);
        let verifier = SumcheckVerifier::new(vars);
        let mut rng = thread_rng();
        let mut rand_fr = || rng.gen::<Fr>();
        let mut sumc = Fr::from(0);
        let mut rand_eval = || {
            let a = rand_fr();
            let (b, c) = (a, a);
            sumc += a * a;
            Eval { a, b, c }
        };
        let mle: Vec<Eval> = (0..domain_size).map(|_| rand_eval()).collect();

        //this should depend on mle in a real case
        let r = vec![rand_fr(); vars];
        let r = MultiPoint::new(r);

        let proof = prover.prove(&r, mle.clone(), &());

        let sum = sumc;
        let c = verifier.verify(&r, proof, sum).unwrap();

        let evals = EvalsExt::eval(mle, r);
        let check = verifier.check_evals_at_r(evals, c, &());
        assert!(check);
    }
}
