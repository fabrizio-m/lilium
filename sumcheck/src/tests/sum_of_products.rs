use crate::{
    polynomials::simple_eval::SimpleEval,
    sumcheck::{Env, EvalKind, NoChallIdx, NoChallenges, SumcheckFunction, Var},
    tests::prove_and_verify,
};
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use std::fmt::Debug;

const VARS: usize = 4;
const EVALS: usize = 1 << VARS;

struct SumOfProducts;

impl<F: Field> SumcheckFunction<F> for SumOfProducts {
    type Idx = usize;

    type Mles<V: Copy + Debug> = SimpleEval<V, 2>;

    type ChallIdx = NoChallIdx;
    type Challs = NoChallenges<F>;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        env: E,
        _challs: &Self::Challs,
    ) -> V {
        let a = env.get(0);
        let b = env.get(1);
        a * b
    }

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(f)
    }
}
const fn kinds() -> SimpleEval<EvalKind, 2> {
    SimpleEval::new([EvalKind::FixedSmall; 2])
}

fn test<F: Field>() {
    let mut rng = StdRng::seed_from_u64(4);
    let mut elem = || F::rand(&mut rng);

    let mut evals = vec![];

    let mut sum = F::zero();
    for _ in 0..EVALS {
        let a = elem();
        let b = elem();
        sum += a * b;
        let eval = [a, b];
        evals.push(SimpleEval::new(eval));
    }
    prove_and_verify::<F, SumOfProducts>(evals, sum, NoChallenges::default());
}

#[test]
fn sum_of_products() {
    test::<ark_vesta::Fq>();
}
