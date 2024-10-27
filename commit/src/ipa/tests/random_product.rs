use crate::ipa::IpaScheme;
// use ark_vesta::Affine;
use ark_vesta::Fr;
use ark_vesta::Projective;

type Scheme = IpaScheme<Fr, Projective>;
#[test]
fn random_product() {
    let scheme = Scheme::init(4, None);
}
