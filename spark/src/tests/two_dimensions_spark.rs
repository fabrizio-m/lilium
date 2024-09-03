use crate::{
    challenges::SparkChallenges,
    evals::SparkEval,
    spark::SparkEvalCheck,
    structure::{DimensionStructure, SparkStructure},
};
use ark_ff::Field;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::BTreeMap, iter::successors};
use sumcheck::{
    polynomials::{EvalsExt, MultiPoint, SingleEval},
    sumcheck::{SumcheckProver, SumcheckVerifier},
};

// creating a sparse polynomial of 8 vars and representing it
// as 2 polynomials of 4 vars, then checking the evaluation
// at a random point is the same

const HALF_VARS: usize = 4;

fn sample_poly<F: Field, R: Rng>(rng: &mut R) -> Vec<(usize, F)> {
    let len = 1 << HALF_VARS;
    let mut non_zero_elements = BTreeMap::new();
    while non_zero_elements.len() < len {
        let key: usize = rng.gen();
        let key = key % (len * len);
        if !non_zero_elements.contains_key(&key) {
            let eval: F = F::rand(rng);
            non_zero_elements.insert(key, eval);
        }
    }
    non_zero_elements.into_iter().collect()
}

fn dense_poly<F: Field>(samples: &[(usize, F)]) -> Vec<F> {
    let len = 1 << (HALF_VARS * 2);
    let mut poly = vec![F::zero(); len];
    for (i, eval) in samples {
        poly[*i] = *eval;
    }
    poly
}

fn sparse_poly<F: Field>(samples: &[(usize, F)]) -> SparkStructure<F, 2> {
    let len = 1 << HALF_VARS;
    let mut lookup_low = Vec::with_capacity(len);
    let mut lookup_high = Vec::with_capacity(len);
    let mut counts_low = vec![0; len];
    let mut counts_high = vec![0; len];
    let mut evals = Vec::with_capacity(len);
    for (i, eval) in samples {
        // let i_low = i & 0b1111;
        let i_low = i & ((1 << HALF_VARS) - 1);
        let i_high = i >> HALF_VARS;
        evals.push(*eval);

        lookup_low.push(i_low);
        lookup_high.push(i_high);
        counts_low[i_low] += 1;
        counts_high[i_high] += 1;
    }
    let dim_low = DimensionStructure::new(counts_low, lookup_low);
    let dim_high = DimensionStructure::new(counts_high, lookup_high);

    let normal_index = successors(Some(0_u32), |x| Some(x + 1))
        .map(F::from)
        .take(len)
        .collect();
    let dimensions = [dim_low, dim_high];
    let val = evals;
    SparkStructure {
        dimensions,
        normal_index,
        val,
    }
}

fn test<F: Field>() {
    let mut rng = StdRng::seed_from_u64(3);
    let samples = sample_poly(&mut rng);
    let mut elem = || F::rand(&mut rng);

    let eval_point_low = vec![elem(); HALF_VARS];
    let eval_point_high = vec![elem(); HALF_VARS];
    let eval_point = MultiPoint::new(
        eval_point_low
            .iter()
            .chain(&eval_point_high)
            .cloned()
            .collect(),
    );

    let r = vec![elem(); HALF_VARS];
    let r = MultiPoint::new(r);

    let dense_poly = dense_poly(&samples);
    let dense_poly = SingleEval::from_field_elements(&dense_poly);
    let true_eval = EvalsExt::eval(dense_poly, eval_point);
    println!("true eval: {}", true_eval.0);
    let structure = sparse_poly(&samples);

    let points = [eval_point_low, eval_point_high].map(MultiPoint::new);
    let challenges = SparkChallenges::new(elem(), elem(), elem());
    let zero_check_point = vec![elem(); HALF_VARS];
    let zero_check_point = MultiPoint::new(zero_check_point);
    let mle = SparkEval::evals(&structure, points, challenges, zero_check_point);

    let sum = SumcheckProver::<F, SparkEvalCheck<2>>::new(HALF_VARS);
    let challs = &challenges;
    let proof = sum.prove(&r, mle.clone(), challs);

    let verifier = SumcheckVerifier::<F, SparkEvalCheck<2>>::new(HALF_VARS);
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
fn sparse_dense_eq() {
    test::<ark_vesta::Fq>();
}
