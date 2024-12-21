use crate::ipa::poly_comm::IpaCommitmentScheme;
use crate::CommmitmentScheme;
use ark_ff::UniformRand;
use ark_vesta::{Fr, Projective};
use rand::thread_rng;
use sumcheck::polynomials::MultiPoint;

type Scheme = IpaCommitmentScheme<Fr, Projective>;

const LEN_LOG: usize = 4;
const LEN: usize = 1 << LEN_LOG;

#[test]
fn polynomial_commitment() {
    let scheme: Scheme = <Scheme as CommmitmentScheme<Fr>>::new(LEN_LOG);

    let mut rng = thread_rng();

    let mut elem = || Fr::rand(&mut rng);

    let mle: Vec<Fr> = vec![elem(); LEN];

    let commit = scheme.commit_mle(&mle);

    let point: Vec<Fr> = vec![elem(); LEN_LOG];
    let point = MultiPoint::new(point);

    let (eval, open) = scheme.open(&mle, commit, &point, None);

    let verify = scheme.verify(commit, &point, eval, open);
    assert!(verify);
}

#[test]
#[should_panic]
fn polynomial_commitment_fail() {
    let scheme: Scheme = <Scheme as CommmitmentScheme<Fr>>::new(LEN_LOG);

    let mut rng = thread_rng();

    let mut elem = || Fr::rand(&mut rng);

    let mle: Vec<Fr> = vec![elem(); LEN];

    let commit = scheme.commit_mle(&mle);

    let point: Vec<Fr> = vec![elem(); LEN_LOG];
    let point = MultiPoint::new(point);

    let (eval, open) = scheme.open(&mle, commit, &point, None);
    let eval = eval * eval;

    let verify = scheme.verify(commit, &point, eval, open);
    assert!(verify);
}
