use crate::ipa::{self, sponge::SimpleSponge, IpaScheme};
use ark_ff::{UniformRand, Zero};
use ark_vesta::{Fr, Projective};
use rand::thread_rng;

type Scheme = IpaScheme<Fr, Projective>;
type Proof = ipa::Proof<Fr, Projective>;

const LEN_LOG: usize = 4;
const LEN: usize = 1 << LEN_LOG;

// proving an inner prover between 2 random vector4
#[test]
fn random_product() {
    let scheme: Scheme = Scheme::init(LEN_LOG, None);

    let mut rng = thread_rng();

    let mut elem = || Fr::rand(&mut rng);

    let a: Vec<Fr> = vec![elem(); LEN];
    let b: Vec<Fr> = vec![elem(); LEN];

    let commit = scheme.commit(&a);

    let inner_product: Fr = a
        .iter()
        .zip(b.iter())
        .fold(Fr::zero(), |acc, (a, b)| acc + *a * b);
    let inner_product = Some(inner_product);
    let mut sponge = SimpleSponge::default();
    let proof: Proof = scheme.prove([a, b.clone()], inner_product, commit, &mut sponge);

    let mut sponge = SimpleSponge::default();
    let inner_product = inner_product.unwrap();
    let verified = scheme.verify(&mut sponge, commit, b, inner_product, proof);
    assert!(verified);
}
