use crate::{
    ipa::{IpaScheme, Proof},
    CommmitmentScheme, OpenInstance,
};
use ark_ec::{AffineRepr, CurveConfig, CurveGroup, Group, VariableBaseMSM};
use ark_ff::PrimeField;
use hash_to_curve::CurveMap;
use sponge::sponge::Duplex;
use std::ops::{Add, Mul};
use sumcheck::eq::eq;
use transcript::{
    messages::{ForeignElement, SingleElement},
    params::ParamResolver,
    protocols::Protocol,
    utils::cycle_cast,
    Message, MessageGuard, Transcript,
};

use super::{
    vector_utils::{challenge_combinations, compute_inner_product},
    RoundMsg,
};

#[derive(Debug, Clone)]
pub struct IpaCommitmentScheme<F, G, M>(IpaScheme<F, G, M>)
where
    F: PrimeField,
    G: VariableBaseMSM<ScalarField = F> + CurveGroup,
    M: CurveMap<G>;

#[derive(Clone, Debug)]
pub struct IpaCommitment<G>(pub(crate) G);

type Scalar<G> = <G as Group>::ScalarField;

impl<G: CurveGroup> Message<Scalar<G>> for IpaCommitment<G> {
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        4
    }

    fn to_field_elements(&self) -> Vec<<G::Config as CurveConfig>::ScalarField> {
        let affine = self.0.into_affine();
        let (x, y) = affine.xy().unwrap();
        let mut elems = Vec::with_capacity(4);
        [*x, *y]
            .map(ForeignElement::<G::BaseField, Scalar<G>>::from)
            .into_iter()
            .for_each(|x| {
                elems.extend(x.to_field_elements());
            });
        elems
    }
}
impl<G: CurveGroup> Mul<Scalar<G>> for IpaCommitment<G> {
    type Output = Self;

    fn mul(self, rhs: Scalar<G>) -> Self::Output {
        Self(self.0 * rhs)
    }
}
impl<G: CurveGroup> Add<&Self> for IpaCommitment<G> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}
impl<G: CurveGroup> Add for IpaCommitment<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

#[derive(Debug, Clone)]
pub enum IpaError {
    Transcript(transcript::Error),
    /// The final folded commitment doesn't open to the expected value
    FinalOpenMismatch,
}

impl From<transcript::Error> for IpaError {
    fn from(value: transcript::Error) -> Self {
        Self::Transcript(value)
    }
}

impl<F, G, M> Protocol<F> for IpaCommitmentScheme<F, G, M>
where
    F: PrimeField,
    G: VariableBaseMSM<ScalarField = F> + CurveGroup,
    M: CurveMap<G>,
{
    type Key = Self;

    type Instance = OpenInstance<F, IpaCommitment<G>>;

    type Proof = Proof<F, G>;

    type Error = IpaError;

    fn transcript_pattern(
        _key: &Self,
        builder: transcript::TranscriptBuilder,
    ) -> transcript::TranscriptBuilder {
        builder
            .round::<F, Self::Instance, 1>()
            .fold_rounds::<F, RoundMsg<G>, 1>()
            .round::<F, SingleElement<F>, 0>()
    }

    fn prove(_instance: Self::Instance) -> Self::Proof {
        todo!()
    }

    fn verify<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::Instance>,
        mut transcript: transcript::TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<(), Self::Error> {
        let (ins, [u]) = transcript.unwrap_guard(instance)?;
        // casting challeng u into the base field, and then mapping to curve point
        let u: G::BaseField = cycle_cast(u);
        let u = key.0.map.map_to_curve(u);

        let OpenInstance {
            commit,
            point,
            eval,
        } = ins;

        let commitment: G = commit.0 + u * eval;
        let mut challenges = vec![];
        let messages = transcript.receive_message_delayed(|proof| {
            proof
                .messages
                .iter()
                .cloned()
                .map(RoundMsg::from)
                .collect::<Vec<_>>()
        });
        let messages: Vec<MessageGuard<RoundMsg<G>>> = messages.transpose();

        let commitment: Result<G, transcript::Error> =
            messages.into_iter().try_fold(commitment, |acc, msg| {
                let (msg, [chall]) = transcript.unwrap_guard(msg)?;
                let RoundMsg { cl, cr } = msg;
                challenges.push(chall);
                let commit = acc + cl * chall.square() + cr * chall.inverse().unwrap().square();
                Ok(commit)
            });
        let commitment: G = commitment?;

        let mut challs_inv = challenges.clone();
        ark_ff::fields::batch_inversion(&mut challs_inv);

        // Efficient way of folding vectors by a single msm/inner product
        // with the s vector.
        let s = challenge_combinations(&challenges, &challs_inv);

        // "a" the single value openened from the resulting folded commitment to
        // the length 1 vector.
        // Note: doesn't really need to be absorbed, but it probably isn't an
        // issue to do it anyway.
        let (SingleElement(a), []) = transcript
            .receive_message(|proof| SingleElement(proof.a))
            .unwrap();

        let b = eq(&point);
        let folded_b = compute_inner_product(&s, &b);
        let folded_g = G::msm_unchecked(&key.0.vector_basis, &s);

        // TODO: zk opening not revealing a
        // Checking that C = aG + abU
        let open = (u * folded_b + folded_g) * a;
        if commitment == open {
            Ok(())
        } else {
            Err(IpaError::FinalOpenMismatch)
        }
    }
}

impl<F, G, M> CommmitmentScheme<F> for IpaCommitmentScheme<F, G, M>
where
    F: PrimeField,
    G: VariableBaseMSM<ScalarField = F> + CurveGroup,
    M: CurveMap<G>,
{
    type Commitment = IpaCommitment<G>;

    type OpenProof = Proof<F, G>;

    fn new(vars: usize) -> Self {
        Self(IpaScheme::init(vars, None))
    }

    fn commit_mle(&self, evals: &[F]) -> Self::Commitment {
        IpaCommitment(self.0.commit(evals))
    }

    fn commit_small_set(&self, evals: &[u8], set: [F; 256]) -> Self::Commitment {
        IpaCommitment(self.0.commit_small_set(evals, set))
    }

    fn commit_bytes(&self, evals: &[u8]) -> Self::Commitment {
        IpaCommitment(self.0.commit_bytes(evals))
    }

    fn open_instance(
        &self,
        commitment: Self::Commitment,
        point: sumcheck::polynomials::MultiPoint<F>,
        evals: &[F],
    ) -> OpenInstance<F, Self::Commitment> {
        let b = eq(&point);
        let eval = compute_inner_product(evals, &b);
        OpenInstance {
            commit: commitment,
            point,
            eval,
        }
    }
    fn open_prove<S: Duplex<F>>(
        &self,
        instance: OpenInstance<F, Self::Commitment>,
        evals: &[F],
        transcript: &mut Transcript<F, S>,
    ) -> Result<Self::OpenProof, IpaError> {
        let a = evals;
        let b = eq(&instance.point);
        let vectors = [a.to_vec(), b];

        Ok(self.0.prove(vectors, instance, transcript)?)
    }
}
