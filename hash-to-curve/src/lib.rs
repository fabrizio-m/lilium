use ark_ec::CurveGroup;

pub mod svdw;

pub trait CurveMap<G: CurveGroup>: Clone {
    fn new() -> Self;
    fn map_to_curve(&self, u: G::BaseField) -> G;
}
