use crate::{
    polynomials::{simple_eval::SimpleEval, EvalsExt, MultiPoint},
    sumcheck::{Env, SumcheckFunction, SumcheckProver, SumcheckVerifier, Var},
    utils::{ZeroCheck, ZeroCheckAvailable},
};
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};

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

    type Mles = Evals<F>;

    type Challs = ();

    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E, _challs: &Self::Challs) -> V {
        let a = env.get(1);
        let b = env.get(2);
        let c = env.get(3);
        let res = a * b - c;
        let zero_check = ZeroCheck(res);
        ZeroCheckAvailable::zero_check(&env, zero_check).0
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

    let prover = SumcheckProver::<F, MulGate>::new(VARS);

    let r = vec![elem(); VARS];
    let r = MultiPoint::new(r);

    let proof = prover.prove(&r, evals.clone(), &());

    let verifier = SumcheckVerifier::<F, MulGate>::new(VARS);

    let c = verifier.verify(&r, proof, F::zero()).unwrap();

    let evals = EvalsExt::eval(evals, r);
    let verifies = verifier.check_evals_at_r(evals, c, &());
    assert!(verifies);
}

#[test]
fn zero_check() {
    test::<ark_vesta::Fq>();
}
