use crate::{
    polynomials::{simple_eval::SimpleEval, EvalsExt, MultiPoint},
    sumcheck::{Env, SumcheckFunction, SumcheckProver, SumcheckVerifier, Var},
};
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};

const VARS: usize = 4;
const EVALS: usize = 1 << VARS;

struct SumOfProducts;

impl<F: Field> SumcheckFunction<F> for SumOfProducts {
    type Idx = usize;

    type Mles = SimpleEval<F, 2>;

    type Challs = ();

    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E, _challs: &Self::Challs) -> V {
        let a = env.get(0);
        let b = env.get(1);
        a * b
    }
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

    let prover = SumcheckProver::<F, SumOfProducts>::new(VARS);

    let r = vec![elem(); VARS];
    let r = MultiPoint::new(r);

    let proof = prover.prove(&r, evals.clone(), &());

    let verifier = SumcheckVerifier::<F, SumOfProducts>::new(VARS);

    let c = verifier.verify(&r, proof, sum).unwrap();

    let evals = EvalsExt::eval(evals, r);
    let verifies = verifier.check_evals_at_r(evals, c, &());
    assert!(verifies);
}

#[test]
fn sum_of_products() {
    test::<ark_vesta::Fq>();
}
