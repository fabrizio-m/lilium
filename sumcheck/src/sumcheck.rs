use crate::{
    barycentric_eval::BarycentricWeights,
    degree::DegreeEnv,
    eval_check::EvalCheckEnv,
    message::{Message, MessageEnv},
    polynomials::{Evals, EvalsExt, MultiPoint},
    SumcheckError,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign, Sub},
};
use transcript::{instances::PolyEvalCheck, protocols::Reduction, Transcript, TranscriptGuard};

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

pub fn sumcheck_degree<F: Field, SF: SumcheckFunction<F>>() -> usize {
    let degree_env = DegreeEnv::new();
    let challs = <SF::Challs as Default>::default();
    let degree = SF::function(degree_env, &challs);
    degree.0
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
        sumcheck_degree::<F, SF>()
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
    pub fn prove<D: Duplex<F>>(
        &self,
        transcript: &mut Transcript<F, D>,
        mle: Vec<SF::Mles<F>>,
        challs: &SF::Challs,
    ) -> Result<Proof<F, SF>, SumcheckError> {
        let mut messages = Vec::with_capacity(self.vars);

        let _ = (0..self.vars).try_fold(mle, |mle, _| {
            let mle: Vec<SF::Mles<F>> = mle;
            let m = self.message(&mle, challs);
            let [var] = transcript
                .send_message(&m)
                .map_err(SumcheckError::TranscriptError)?;
            messages.push(m);
            Ok(EvalsExt::fix_var(mle, var))
        })?;

        Ok(Proof {
            messages,
            _f: PhantomData,
        })
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
        sumcheck_degree::<F, SF>() as u32
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

pub struct Sum<F>(pub F);
impl<F: Field> transcript::Message<F> for Sum<F> {
    fn len(_vars: usize, _degree: usize) -> usize {
        //1
        0
    }

    fn to_field_elements(&self) -> Vec<F> {
        // vec![self.0]
        vec![]
    }
}

impl<F: Field, SF: SumcheckFunction<F>> Reduction<F> for SumcheckVerifier<F, SF> {
    type A = Sum<F>;

    type B = PolyEvalCheck<F>;

    type Key = Self;

    type Proof = Proof<F, SF>;

    type Error = SumcheckError;

    fn transcript_pattern(
        builder: transcript::TranscriptBuilder<F>,
    ) -> transcript::TranscriptBuilder<F> {
        builder.fold_rounds::<Message<F>, 1>()
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: transcript::GuardedIntance<Self::A>,
        transcript: &mut TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        // let (sum, []) = transcript
        // .unwrap_instance_unsafe(instance)
        // .map_err(SumcheckError::TranscriptError)?;
        let sum = transcript.unwrap_instance_unsafe(instance);
        let mut sum = sum.0;
        let mut vars = vec![];
        for i in 0..key.vars {
            let (message, [r]) = transcript
                .receive_message(|proof| proof.messages[i].clone())
                .map_err(SumcheckError::TranscriptError)?;
            if message.degree() != key.degree {
                return Err(SumcheckError::MessageDegree);
            }
            let e0 = message.eval_at_0();
            let e1 = message.eval_at_1();
            if e0 + e1 != sum {
                return Err(SumcheckError::RoundSum);
            }
            vars.push(r);
            sum = message.eval_at_x(r, &key.weights);
        }
        // as sumcheck handles the point in the opposite way
        // TODO: stablish a stricter point representation.
        vars.reverse();
        let eval = sum;
        Ok(PolyEvalCheck { vars, eval })
    }
}
