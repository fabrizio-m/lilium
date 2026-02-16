#[cfg(test)]
use rand::{rngs::StdRng, SeedableRng};
use sponge::sponge::UnsafeSponge;
use std::fmt::Debug;
use transcript::{protocols::Reduction, MessageGuard, TranscriptBuilder};

use crate::{
    folding::prover::SumFoldProverOutput,
    polynomials::{simple_eval::SimpleEval, SingleEval},
    sumcheck::{Env, EvalKind, NoChallIdx, NoChallenges, SumcheckVerifier, Var},
};

use super::*;

struct Evals<F> {
    a: F,
    b: F,
    c: F,
}

struct Product;

const fn kinds() -> SimpleEval<EvalKind, 3> {
    SimpleEval::new([EvalKind::Virtual; 3])
}

impl<F: Field> SumcheckFunction<F> for Product {
    type Idx = usize;

    type Mles<V: Copy + std::fmt::Debug> = SimpleEval<V, 3>;

    type Challs = NoChallenges<F>;

    type ChallIdx = NoChallIdx;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + std::fmt::Debug,
        B: Copy + std::fmt::Debug,
        M: Fn(A) -> B,
    {
        evals.map(f)
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(env: E) -> V {
        let a = env.get(0);
        let b = env.get(1);
        let c = env.get(2);
        a * b - c
    }

    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        env: E,
    ) -> Option<V> {
        let a = env.get(0);
        let b = env.get(1);
        let c = env.get(2);
        Some(a * b - c)
    }
}

const VARS: usize = 4;

#[cfg(test)]
fn fold_and_prove<F: Field>() {
    let vars = VARS;
    let mut w = vec![];

    let mut rng = StdRng::seed_from_u64(0);

    for _ in 0..(1 << (vars + 1)) {
        let a = F::rand(&mut rng);
        let b = F::rand(&mut rng);
        let c = a * b;
        let eval = SimpleEval::new([a, b, c]);
        w.push(eval);
    }
    let mut w = w.into_iter();
    let w1 = w.by_ref().take(1 << vars).collect::<Vec<_>>();
    let w2 = w.by_ref().take(1 << vars).collect::<Vec<_>>();

    // checking sumcheck individually
    {
        check_sumcheck(F::zero(), w1.clone());
        check_sumcheck(F::zero(), w2.clone());
    }

    let sumfold_key = SumFold::<F, _>::new(&Product);

    let transcript_desc = TranscriptBuilder::new(VARS, ParamResolver::new())
        .add_reduction_patter::<F, SumFold<F, _>>(&sumfold_key)
        .finish::<F, UnsafeSponge<F>>();

    let (w3, instance) = {
        let mut transcript = transcript_desc.instanciate();
        let instance = SumFoldInstance::new([F::zero(), F::zero()]);
        let SumFoldProverOutput {
            instance,
            folded_witness,
            proof,
        } = sumfold_key.fold(
            w1,
            &w2,
            Some(instance),
            &mut transcript,
            NoChallenges::default(),
        );
        transcript.finish_unchecked();

        let mut transcript = transcript_desc.instanciate();
        let instance = MessageGuard::new(instance);
        let reduced =
            SumFold::verify_reduction(&sumfold_key, instance, transcript.guard(proof)).unwrap();
        transcript.finish_unchecked();
        (folded_witness, reduced)
    };
    check_sumcheck(instance.0, w3);
}

#[cfg(test)]
fn check_sumcheck<F: Field>(sum: F, witness: Vec<SimpleEval<F, 3>>) {
    let vars = VARS;
    let prover = SumcheckProver::<F, Product>::new(vars);
    let verifier = SumcheckVerifier::new_symbolic(Product, vars);
    let builder = TranscriptBuilder::new(vars, ParamResolver::new());
    let transcript_desc = SumcheckVerifier::<F, Product>::transcript_pattern(&verifier, builder)
        .finish::<F, UnsafeSponge<F>>();

    let out = {
        let mut transcript = transcript_desc.instanciate();
        let out = prover
            .prove(&mut transcript, witness, &NoChallenges::default())
            .unwrap();
        transcript.finish_unchecked();
        out
    };

    let reduced = {
        let mut transcript = transcript_desc.instanciate();
        let instance = MessageGuard::new(Sum(sum));
        // let transcript = transcript.guard(out.proof);

        let reduced =
            SumcheckVerifier::verify_reduction(&verifier, instance, transcript.guard(out.proof))
                .unwrap();
        transcript.finish_unchecked();
        reduced
    };
    let checks = verifier.check_evals_at_r(out.evals, reduced.eval, &NoChallenges::default());
    assert!(checks);
}

#[test]
fn sumfold() {
    use ark_vesta::Fr;
    fold_and_prove::<Fr>();
}
