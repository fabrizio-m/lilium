use crate::{
    ipa::{sponge::SimpleSponge, IpaScheme, Proof},
    CommmitmentScheme,
};
use ark_ec::VariableBaseMSM;
use ark_ff::PrimeField;
use sumcheck::eq::eq;

pub struct IpaCommitmentScheme<F, G>(IpaScheme<F, G>)
where
    F: PrimeField,
    G: VariableBaseMSM<ScalarField = F>;

impl<F, G> CommmitmentScheme<F> for IpaCommitmentScheme<F, G>
where
    F: PrimeField,
    G: VariableBaseMSM<ScalarField = F>,
{
    type Commitment = G;

    type OpenProof = Proof<F, G>;

    fn new(vars: usize) -> Self {
        //TODO: maybe change
        Self(IpaScheme::init(vars, None))
    }

    fn commit_mle(&self, evals: &[F]) -> Self::Commitment {
        self.0.commit(evals)
    }

    fn open(
        &self,
        evals: &[F],
        commitment: Self::Commitment,
        point: &sumcheck::polynomials::MultiPoint<F>,
        eval: Option<F>,
    ) -> Self::OpenProof {
        let a = evals;
        let b = eq(point.clone());
        //TODO: maybe acept sponge as argument
        let mut sponge = SimpleSponge::default();
        let inner_product = eval.or_else(|| {
            let x = a
                .iter()
                .zip(b.iter())
                .fold(F::zero(), |acc, (a, b)| acc + *a * b);
            Some(x)
        });
        let vectors = [a.to_vec(), b];
        let open = self
            .0
            .prove(vectors, inner_product, commitment, &mut sponge);
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
        self.0
            .verify(&mut sponge, commitment, b, inner_product, proof)
    }
}
