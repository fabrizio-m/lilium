use crate::{
    ipa::{sponge::SimpleSponge, IpaScheme, Proof},
    CommmitmentScheme,
};
use ark_ec::VariableBaseMSM;
use ark_ff::PrimeField;
use sumcheck::eq::eq;

impl<F, G> CommmitmentScheme<F> for IpaScheme<F, G>
where
    F: PrimeField,
    G: VariableBaseMSM<ScalarField = F>,
{
    type Commitment = G;

    type OpenProof = Proof<F, G>;

    fn new(vars: usize) -> Self {
        //TODO: maybe change
        IpaScheme::init(vars, None)
    }

    fn commit_mle(&self, evals: &[F]) -> Self::Commitment {
        self.commit(evals)
    }

    fn open(
        &self,
        evals: &[F],
        commitment: Self::Commitment,
        point: &sumcheck::polynomials::MultiPoint<F>,
        eval: F,
    ) -> Self::OpenProof {
        let a = evals;
        let b = eq(point.clone());
        let vectors = [a.to_vec(), b];
        //TODO: maybe acept sponge as argument
        let mut sponge = SimpleSponge::default();
        let inner_product = Some(eval);
        let open = self.prove(vectors, inner_product, commitment, &mut sponge);
        open
    }

    fn verify(
        &self,
        commitment: Self::Commitment,
        point: &sumcheck::polynomials::MultiPoint<F>,
        eval: F,
        proof: Self::OpenProof,
    ) -> bool {
        let b = eq(point.clone());
        let mut sponge = SimpleSponge::default();
        let inner_product = eval;
        self.verify(&mut sponge, commitment, b, inner_product, proof)
    }
}
