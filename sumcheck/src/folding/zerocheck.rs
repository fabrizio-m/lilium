//! ZeroCheck example and test, 2 instances are created, folded and the
//! folded instance is proved and verified.

use crate::{
    folding::{prover::SumFoldProverOutput, SumFold, SumFoldInstance},
    polynomials::simple_eval::SimpleEval,
    prove_and_verify,
    sumcheck::{Env, EvalKind, NoChallIdx, NoChallenges, SumcheckFunction, Var},
    zerocheck::CompactPowers,
};
use ark_ff::Field;
use sponge::sponge::UnsafeSponge;
use std::fmt::Debug;
use transcript::{
    params::ParamResolver, protocols::Reduction, MessageGuard, TranscriptBuilder, TranscriptGuard,
};

struct ZeroCheck;

const fn kinds() -> SimpleEval<EvalKind, 4> {
    SimpleEval::new([EvalKind::Virtual; 4])
}

impl<F: Field> SumcheckFunction<F> for ZeroCheck {
    type Idx = usize;

    type Mles<V: Copy + Debug> = SimpleEval<V, 4>;

    type Challs = NoChallenges<F>;

    type ChallIdx = NoChallIdx;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(f)
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(env: E) -> V {
        let a = env.get(0);
        let b = env.get(1);
        let c = env.get(2);
        let z = env.get(3);
        z * (a + b - c)
    }

    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        env: E,
    ) -> Option<V> {
        let a = env.get(0);
        let b = env.get(1);
        let c = env.get(2);
        let z = env.get(3);
        Some(z * (a + b - c))
    }
}

const VARS: usize = 5;

#[derive(Clone)]
struct InstanceWitness<F: Field> {
    witness: Vec<SimpleEval<F, 4>>,
    powers: CompactPowers<F>,
}

fn sample_instance_witness<F: Field>(elems: Vec<F>) -> InstanceWitness<F> {
    assert!(elems.len() > (1 << VARS) * 2);
    let mut evals = vec![];
    let mut elems = elems.into_iter();
    let chall = elems.next().unwrap();
    let compact_powers = CompactPowers::new(chall, VARS);
    let mut powers = compact_powers.clone().eval_over_domain().into_iter();
    for _ in 0..(1 << VARS) {
        let a = elems.next().unwrap();
        let b = elems.next().unwrap();
        let c = a + b;
        let z = powers.next().unwrap();
        evals.push(SimpleEval::new([a, b, c, z]));
    }
    InstanceWitness {
        witness: evals,
        powers: compact_powers,
    }
}

fn check_pair<F: Field>(pair: InstanceWitness<F>, sum: F) {
    let InstanceWitness { witness, powers } = pair;
    let (evals, r) = prove_and_verify::<F, ZeroCheck>(witness, sum, NoChallenges::default());
    assert_eq!(powers.point_eval(&r), evals.inner()[3]);
}

fn test<F: Field>(random_elements: Vec<F>) {
    let mut elements = random_elements.into_iter();

    let pair1 = sample_instance_witness::<F>(elements.by_ref().take((1 << VARS) * 2 + 1).collect());
    let pair2 = sample_instance_witness::<F>(elements.by_ref().take((1 << VARS) * 2 + 1).collect());

    check_pair(pair1.clone(), F::zero());
    check_pair(pair2.clone(), F::zero());

    let sumfold_key = SumFold::<F, _>::new(&ZeroCheck);

    let (mut witness, sum, folder) = {
        let transcript_desc = TranscriptBuilder::new(VARS, ParamResolver::new())
            .add_reduction_patter::<F, SumFold<F, _>>(&sumfold_key)
            .finish::<F, UnsafeSponge<F>>();

        let mut transcript = transcript_desc.instanciate();

        let instance = SumFoldInstance::new([F::zero(), F::zero()]);
        let sums = Some(instance);
        let w1 = pair1.witness.clone();
        let w2 = pair2.witness.as_slice();

        let SumFoldProverOutput {
            instance,
            folded_witness,
            proof,
            folder,
        } = sumfold_key.fold(w1, w2, sums, &mut transcript, NoChallenges::default());
        transcript.finish_unchecked();

        let mut transcript = transcript_desc.instanciate();
        let transcript_guard = TranscriptGuard::new(&mut transcript, proof);
        let instance = MessageGuard::new(instance);

        let instance = SumFold::verify_reduction(&sumfold_key, instance, transcript_guard).unwrap();
        transcript.finish_unchecked();
        (folded_witness, instance, folder)
    };

    let powers = folder.fold_powers(pair1.powers, pair2.powers);
    {
        let powers = powers.clone().eval_over_domain();
        for (w, power) in witness.iter_mut().zip(powers) {
            let mut row = *w.inner();
            row[3] = power;
            *w = SimpleEval::new(row);
        }
    }
    let pair = InstanceWitness { witness, powers };

    check_pair(pair, sum.0);
}

#[test]
fn fold_zerocheck() {
    use ark_ff::UniformRand;
    use ark_vesta::Fr;
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter::repeat;

    let mut rng = StdRng::seed_from_u64(0);
    let elems = repeat(()).map(|_| Fr::rand(&mut rng));
    let elems = elems.take((1 << VARS) * 4 + 2).collect();
    test(elems);
}
