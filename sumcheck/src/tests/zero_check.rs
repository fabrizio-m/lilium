use crate::{
    polynomials::{simple_eval::SimpleEval, MultiPoint},
    sumcheck::{Env, EvalKind, SumcheckFunction, Var},
    tests::prove_and_verify,
    utils::{ZeroCheck, ZeroCheckAvailable},
};
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use std::fmt::Debug;

const VARS: usize = 4;
const EVALS: usize = 1 << VARS;

#[derive(Clone, Debug, Copy)]
struct MulGate;

// 0: zero check
// 1: a
// 2: b
// 3: c
type Evals<F> = SimpleEval<F, 4>;

impl<F: Field> SumcheckFunction<F> for MulGate {
    type Idx = usize;

    type Mles<V: Copy + Debug> = Evals<V>;

    type Challs = ();

    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E, _challs: &Self::Challs) -> V {
        let a = env.get(1);
        let b = env.get(2);
        let c = env.get(3);
        let res = a * b - c;
        let zero_check = ZeroCheck(res);
        ZeroCheckAvailable::zero_check(&env, zero_check).0
    }

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(f)
    }
    fn eval_kinds() -> Self::Mles<EvalKind> {
        SimpleEval::new([EvalKind::FixedSmall; 4])
    }
}

fn test<F: Field>() {
    let mut rng = StdRng::seed_from_u64(4);
    let mut elem = || F::rand(&mut rng);

    let zero_check_point = vec![elem(); VARS];
    let zero_check_point = MultiPoint::new(zero_check_point);

    let zero_eq = crate::eq::eq(zero_check_point);

    let mut evals = vec![];
    for i in 0..EVALS {
        let a = elem();
        let b = elem();
        let c = a * b;
        let zero = zero_eq[i];
        let eval = [zero, a, b, c];
        evals.push(SimpleEval::new(eval));
    }

    let sum = F::zero();
    prove_and_verify::<F, MulGate>(evals, sum, ());
}

#[test]
fn zero_check() {
    test::<ark_vesta::Fq>();
}
