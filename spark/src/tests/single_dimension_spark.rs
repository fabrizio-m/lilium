use crate::{
    challenges::SparkChallenges,
    evals::SparkEval,
    spark::SparkEvalCheck,
    structure::{DimensionStructure, SparkStructure},
};
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use std::iter::successors;
use sumcheck::{
    polynomials::{EvalsExt, MultiPoint, SingleEval},
    sumcheck::{SumcheckProver, SumcheckVerifier},
};

const VARS: usize = 4;

fn test<F: Field>() {
    let mut rng = StdRng::seed_from_u64(3);
    let len = 1 << VARS;

    let mut elem = || F::rand(&mut rng);
    let evals = vec![elem(); len];

    let eval_point = vec![elem(); VARS];
    let eval_point = MultiPoint::new(eval_point);
    let poly = SingleEval::from_field_elements(&evals);
    let true_eval = EvalsExt::eval(poly, eval_point.clone());

    let r = vec![elem(); VARS];
    let r = MultiPoint::new(r);

    let counts = vec![1; len];
    let lookups = successors(Some(0), |x| Some(x + 1)).take(len).collect();
    let dimension = DimensionStructure::new(counts, lookups);
    let normal_index = dimension.lookups_field.clone();
    let dimensions = [dimension];
    let val = evals;

    let structure = SparkStructure {
        dimensions,
        normal_index,
        val,
    };

    let challenges = SparkChallenges::new(elem(), elem(), elem());
    let zero_check_point = vec![elem(); VARS];
    let zero_check_point = MultiPoint::new(zero_check_point);
    let points = [eval_point];
    let mle = SparkEval::evals(&structure, points, challenges, zero_check_point);

    let sum = SumcheckProver::<F, SparkEvalCheck<1>>::new(VARS);
    let challs = &challenges;
    let proof = sum.prove(&r, mle.clone(), challs);
    println!("proof: {:#?}", &proof);

    let verifier = SumcheckVerifier::<F, SparkEvalCheck<1>>::new(VARS);
    match verifier.verify(&r, proof, true_eval.0) {
        Ok(c) => {
            let evals = EvalsExt::eval(mle, r);
            assert!(verifier.check_evals_at_r(evals, c, challs));
        }
        Err(err) => {
            panic!("{:?}", err);
        }
    }
}

#[test]
fn single_dimension_spark() {
    test::<ark_vesta::Fq>();
}
