use crate::{ipa::poly_comm::IpaCommitmentScheme, CommmitmentScheme};
use ark_ff::{Field, UniformRand};
use ark_vesta::{Fr, Projective, VestaConfig};
use hash_to_curve::svdw::SvdwMap;
use rand::thread_rng;
use sponge::{permutation::UnsafePermutation, sponge::Sponge};
use sumcheck::polynomials::{EvalsExt, MultiPoint, SingleEval};
use transcript::{params::ParamResolver, TranscriptBuilder};

type Scheme = IpaCommitmentScheme<Fr, Projective, SvdwMap<VestaConfig>>;

const LEN_LOG: usize = 4;
const LEN: usize = 1 << LEN_LOG;

type TestSponge = Sponge<Fr, UnsafePermutation<Fr, 3>, 2, 1, 3>;

fn polynomial_commitment<S: CommmitmentScheme<Fr>>(should_fail: bool) {
    let scheme = S::new(LEN_LOG);

    let mut rng = thread_rng();

    let mut elem = || Fr::rand(&mut rng);

    let mut mle: Vec<Fr> = vec![elem(); LEN];

    let commit = scheme.commit_mle(&mle);

    let point: Vec<Fr> = vec![elem(); LEN_LOG];
    let point = MultiPoint::new(point);

    let instance = scheme.open_instance(commit.clone(), point.clone(), &mle);

    let params = ParamResolver::new();
    let transcript_builder =
        TranscriptBuilder::new(LEN_LOG, params).add_protocol_pattern::<Fr, S>(&scheme);
    let transcript_desc = transcript_builder.finish::<Fr, TestSponge>();
    let mut transcript = transcript_desc.instantiate();

    let proof = scheme
        .open_prove(instance.clone(), &mle, &mut transcript)
        .unwrap();
    transcript.finish_unchecked();

    let mut transcript = transcript_desc.instantiate();
    // let mut transcript = TranscriptGuard::new(transcript, proof);
    if should_fail {
        // to make it fail
        mle[0].double_in_place();
    }
    let instance = scheme.open_instance(commit, point, &mle);
    let verify = S::verify(&scheme, instance.into(), transcript.guard(proof));
    transcript.finish_unchecked();

    assert!(verify.is_ok());
}
#[test]
fn ipa_pcs() {
    polynomial_commitment::<Scheme>(false);
}
#[test]
#[should_panic]
fn ipa_pcs_should_fail() {
    polynomial_commitment::<Scheme>(true);
}

// The test above only checks that the opening proof verifies; it never asserts
// that open_instance produces the correct evaluation. For open_instance the
// eval is computed as the eq-dot-product sum of mle_i * eq(point, i). Here we
// verify that with EvalsExt::eval_slow (an algorithmically independent evaluator),
// so that a bug in the eq inner-product path would be caught.
#[test]
fn ipa_open_instance_eval_matches_independent_mle_eval() {
    let scheme = Scheme::new(LEN_LOG);

    let mut rng = thread_rng();
    let mut elem = || Fr::rand(&mut rng);
    let mle: Vec<Fr> = (0..LEN).map(|_| elem()).collect();
    let commit = scheme.commit_mle(&mle);

    let points: Vec<(&str, MultiPoint<Fr>)> = vec![
        ("zero point", MultiPoint::new(vec![Fr::ZERO; LEN_LOG])),
        ("one point", MultiPoint::new(vec![Fr::ONE; LEN_LOG])),
        (
            "random point",
            MultiPoint::new((0..LEN_LOG).map(|_| elem()).collect()),
        ),
    ];

    for (case, point) in points {
        let claimed = scheme
            .open_instance(commit.clone(), point.clone(), &mle)
            .eval();

        let independent = EvalsExt::eval_slow(SingleEval::from_vec(mle.clone()), point).0;

        assert_eq!(
        claimed, independent,
        "IPA open eval via eq-dot-product disagrees with independent recursive MLE evaluation (case: {case})"
    );
    }
}
