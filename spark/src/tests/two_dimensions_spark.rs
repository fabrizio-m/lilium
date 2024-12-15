use crate::{
    challenges::SparkChallenges, evals::SparkEval, spark::SparkEvalCheck, structure::SparkStructure,
};
use ark_ff::Field;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::BTreeMap;
use sumcheck::{
    polynomials::{EvalsExt, MultiPoint, SingleEval},
    sumcheck::{SumcheckProver, SumcheckVerifier},
};

// Creating an sparse 8-variate polynomial and representing it
// as 2 4-variate polynomials, then checking the evaluation
// at a random point is the same.

const HALF_VARS: usize = 4;

/// Creates a random sparse polynomial, speciafically an 8 variate
/// polynomial with at most 2^4 non-zero elements.
/// Returning only the non-zero evaluations as tuples (point, eval)
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

/// Creates the dense polynomial
fn dense_poly<F: Field>(samples: &[(usize, F)]) -> Vec<SingleEval<F>> {
    let len = 1 << (HALF_VARS * 2);
    let mut poly = vec![F::zero(); len];
    for (i, eval) in samples {
        poly[*i] = *eval;
    }
    SingleEval::from_field_elements(&poly)
}

/// Creates the structure representing this sparse polynomial, the structure
/// being mostly a collection of smaller dense polynomials.
fn sparse_poly<F: Field>(samples: &[(usize, F)]) -> SparkStructure<F, 2> {
    let evals = samples
        .into_iter()
        .map(|(index, val)| {
            let i_low = index & ((1 << HALF_VARS) - 1);
            let i_high = index >> HALF_VARS;
            ([i_low, i_high], *val)
        })
        .collect();
    SparkStructure::new(evals)
}

fn test<F: Field>() {
    let mut rng = StdRng::seed_from_u64(3);
    let samples = sample_poly(&mut rng);
    let mut elem = || F::rand(&mut rng);

    // A random point in which to evaluate our polynomial
    let eval_point_low = vec![elem(); HALF_VARS];
    let eval_point_high = vec![elem(); HALF_VARS];
    let eval_point = MultiPoint::new(
        eval_point_low
            .iter()
            .chain(&eval_point_high)
            .cloned()
            .collect(),
    );

    // Random point for sumcheck
    let r = vec![elem(); HALF_VARS];
    let r = MultiPoint::new(r);

    let dense_poly = dense_poly(&samples);
    // Evaluation of the dense polynomial for reference
    let true_eval = EvalsExt::eval(dense_poly, eval_point);

    // The structure for the sparse representation
    let structure = sparse_poly(&samples);

    let points = [eval_point_low, eval_point_high].map(MultiPoint::new);
    // Challenges to be used in this sumcheck run
    let challenges = SparkChallenges::new(elem(), elem(), elem());
    // A random point used to convert zero checks into sumchecks
    let zero_check_point = vec![elem(); HALF_VARS];
    let zero_check_point = MultiPoint::new(zero_check_point);
    // The final collection of mles to be used, it is a vector with as many
    // elements as elements has the domain.
    // And each elements it a type containing the evaluation of each mle at
    // that point of the domain.
    let mle = SparkEval::evals(&structure, points, challenges, zero_check_point);

    // create a sumcheck prover using the spark function for 2 dimensions
    let prover = SumcheckProver::<F, SparkEvalCheck<2>>::new(HALF_VARS);
    let challs = &challenges;
    // making a proof
    let proof = prover.prove(&r, mle.clone(), challs);

    // creating a verifier, same as the prover
    let verifier = SumcheckVerifier::<F, SparkEvalCheck<2>>::new(HALF_VARS);
    // verifying the proof for the fiven sum, in this case the evaluation
    // of the committed sparse polynomial
    match verifier.verify(&r, proof, true_eval.0) {
        // If verification passes, the only remaining thing is to check
        // that the sumcheck polynomial SparkEvalCheck<2> defines as a
        // combination of multilinear polynomials evaluates to c at r.
        // In a more real case here we would use polynomial commitments
        // to get the evaluation a r. But for thise test we already have
        // the mles and we can just evaluate them.
        Ok(c) => {
            // Evaluating all the mles at the point r
            let evals = EvalsExt::eval(mle, r);
            // This method will combine the evaluations of the mle
            // into the evaluation of the final single sumcheck polynomial
            // and then check it is equal to c.
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
