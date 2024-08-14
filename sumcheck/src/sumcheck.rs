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
    marker::PhantomData,
    ops::{Add, Mul, Sub},
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
    + Clone
{
}

/// allows access to variables
pub trait Env<F: Field, V, I>
where
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

/// Defines a polynomial used in sumcheck as a function of multilinear
/// polynomials
pub trait SumcheckFunction<F: Field> {
    type Idx: Copy;
    type Mles: Evals<F, Idx = Self::Idx>;

    ///computes the arbitrary degree polynomial as a function of multilinear polynomials
    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E) -> V;
}

pub struct SumcheckProver<F: Field, SF: SumcheckFunction<F>> {
    _phantom: PhantomData<(F, SF)>,
    vars: usize,
    degree: usize,
}

pub struct Proof<F: Field, SF: SumcheckFunction<F>> {
    messages: Vec<Message<F>>,
    _f: PhantomData<SF>,
}

impl<F: Field, SF: SumcheckFunction<F>> SumcheckProver<F, SF> {
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
        let degree = SF::function(degree_env);
        degree.0
    }
    fn message(&self, mle: &[SF::Mles]) -> Message<F> {
        let half_len = mle.len() / 2;
        let (left, right) = mle.split_at(half_len);
        let degree = self.degree;

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
    pub fn prove(&self, r: &MultiPoint<F>, mle: Vec<SF::Mles>) -> Proof<F, SF> {
        assert_eq!(self.vars, r.vars());
        let point = r.clone();
        let mut messages = Vec::with_capacity(self.vars);

        let _ = (0..self.vars).fold((mle, point), |(mle, point), _| {
            let m = self.message(&mle);
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
        let degree = SF::function(degree_env);
        degree.0 as u32
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
    pub fn check_evals_at_r(&self, evals: SF::Mles, c: F) -> bool {
        let env = EvalCheckEnv::new(evals);
        let eval = SF::function(env);
        eval == c
    }
}

#[cfg(test)]
mod test {
    use crate::{
        polynomials::{Evals, EvalsExt, MultiPoint},
        sumcheck::{SumcheckFunction, SumcheckProver, SumcheckVerifier},
    };
    use ark_vesta::Fr;
    use rand::{thread_rng, Rng};
    use std::ops::Index;

    #[derive(Clone, Copy)]
    struct Eval {
        a: Fr,
        b: Fr,
        c: Fr,
    }
    impl Index<usize> for Eval {
        type Output = Fr;

        fn index(&self, index: usize) -> &Self::Output {
            match index {
                0 => &self.a,
                1 => &self.b,
                2 => &self.c,
                _ => {
                    unreachable!()
                }
            }
        }
    }
    impl Evals<Fr> for Eval {
        type Idx = usize;

        fn combine<C: Fn(Fr, Fr) -> Fr>(&self, other: &Self, f: C) -> Self {
            let a = f(self.a, other.a);
            let b = f(self.b, other.b);
            let c = f(self.c, other.c);
            Eval { a, b, c }
        }
    }
    struct MulGate;
    impl SumcheckFunction<Fr> for MulGate {
        type Idx = usize;

        type Mles = Eval;

        fn function<V: super::Var<Fr>, E: super::Env<Fr, V, Self::Idx>>(env: E) -> V {
            let a = env.get(0);
            let b = env.get(1);
            let c = env.get(2);
            (a.clone() * b) - c
        }
    }
    struct SquareGate;
    impl SumcheckFunction<Fr> for SquareGate {
        type Idx = usize;

        type Mles = Eval;

        fn function<V: super::Var<Fr>, E: super::Env<Fr, V, Self::Idx>>(env: E) -> V {
            let a = env.get(0);
            a.clone() * a
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

        let proof = prover.prove(&r, mle.clone());

        let sum = Fr::from(0);
        let c = verifier.verify(&r, proof, sum).unwrap();

        let evals = EvalsExt::eval(mle, r);
        let check = verifier.check_evals_at_r(evals, c);
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

        let proof = prover.prove(&r, mle.clone());

        let sum = sumc;
        let c = verifier.verify(&r, proof, sum).unwrap();

        let evals = EvalsExt::eval(mle, r);
        let check = verifier.check_evals_at_r(evals, c);
        assert!(check);
    }
}
