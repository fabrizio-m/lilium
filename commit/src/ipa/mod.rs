use ::sponge::sponge::Duplex;
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::Field;
use hash_to_curve::CurveMap;
use rand::{rngs::StdRng, SeedableRng};
use vector_utils::{fold_basis, fold_vec};

mod poly_comm;
mod sponge;
#[cfg(test)]
mod tests;
mod vector_utils;

pub use poly_comm::{IpaCommitment, IpaCommitmentScheme, IpaError};

/// computes the 2 crossed commitments between the 2 vector
/// a_low X b_high * G + a_low X g_high
/// a_high X b_low * G + a_high X g_low
fn ipa_reduce<F: Field, G>(vectors: [&[F]; 2], basis: &[G::MulBase], product_base: G) -> [G; 2]
where
    G: VariableBaseMSM<ScalarField = F>,
{
    assert_eq!(vectors[0].len(), vectors[1].len());
    assert_eq!(vectors[0].len(), basis.len());
    let len = basis.len();
    assert!(len.is_power_of_two());
    let half_len = len / 2;
    let [a, b] = vectors;
    let (a_low, a_high) = a.split_at(half_len);
    let (b_low, b_high) = b.split_at(half_len);
    let (g_low, g_high) = basis.split_at(half_len);
    let commit_l = G::msm_unchecked(g_high, a_low);
    let commit_r = G::msm_unchecked(g_low, a_high);
    let inner_product_l = a_low
        .iter()
        .zip(b_high)
        .fold(F::zero(), |acc, (a, b)| acc + *a * b);
    let inner_product_r = a_high
        .iter()
        .zip(b_low)
        .fold(F::zero(), |acc, (a, b)| acc + *a * b);
    let commit_l = product_base * inner_product_l + commit_l;
    let commit_r = product_base * inner_product_r + commit_r;
    [commit_l, commit_r]
}

#[derive(Debug, Clone)]
struct IpaScheme<F, G, M>
where
    F: Field,
    G: VariableBaseMSM<ScalarField = F> + CurveGroup,
    M: CurveMap<G>,
{
    // basis to commit to the non-public vector
    pub vector_basis: Vec<G::MulBase>,
    pub map: M,
}

struct Round<F, G: VariableBaseMSM<ScalarField = F>> {
    a: Vec<F>,
    b: Vec<F>,
    basis: Vec<G::MulBase>,
    commitment: G,
}

impl<F, G: VariableBaseMSM<ScalarField = F>> Round<F, G> {
    // wheter it has been reduced to the minimal instance, with vectors of size 1
    fn reduced(&self) -> bool {
        debug_assert_eq!(self.a.len(), self.b.len());
        debug_assert_eq!(self.basis.len(), self.b.len());
        self.a.len() == 1
    }
}

#[derive(Debug, Clone)]
pub struct Proof<F, G> {
    messages: Vec<(G, G)>,
    a: F,
}

type Res<T> = Result<T, transcript::Error>;

impl<F, G, M> IpaScheme<F, G, M>
where
    F: Field,
    G: VariableBaseMSM<ScalarField = F> + CurveGroup,
    M: CurveMap<G>,
{
    pub fn commit(&self, a: &[F]) -> G {
        assert_eq!(a.len(), self.vector_basis.len());
        G::msm_unchecked(&self.vector_basis, a)
    }

    pub fn commit_small_set(&self, a: &[u8], set: [F; 256]) -> G {
        assert_eq!(a.len(), self.vector_basis.len());
        let mut bucket = [G::zero(); 256];
        for (i, base) in a.iter().zip(&self.vector_basis) {
            bucket[*i as usize] += base;
        }
        let bucket = G::batch_convert_to_mul_base(&bucket);
        G::msm_unchecked(&bucket, &set)
    }

    pub fn commit_bytes(&self, a: &[u8]) -> G {
        assert_eq!(a.len(), self.vector_basis.len());
        let mut bucket = [G::zero(); 256];
        for (i, base) in a.iter().zip(&self.vector_basis) {
            bucket[*i as usize] += base;
        }
        bucket
            .into_iter()
            .skip(1)
            .rev()
            .fold(G::zero(), |acc, byte| acc.double() + byte)
    }

    fn round<S: Duplex<F>>(
        round: Round<F, G>,
        transcript: &mut Transcript<F, S>,
        product_base: G,
    ) -> Res<(Round<F, G>, (G, G))> {
        let Round {
            a,
            b,
            basis,
            commitment,
        } = round;
        let [cl, cr] = ipa_reduce::<F, G>([&a, &b], &basis, product_base);
        let message = RoundMsg { cl, cr };
        let [chall] = transcript.send_message(&message)?;
        let chall_inv = chall.inverse().unwrap();
        let a = fold_vec(a, [chall, chall_inv]);
        let b = fold_vec(b, [chall_inv, chall]);
        let basis = fold_basis::<G>(basis, [chall_inv, chall]);
        let commitment = commitment + cl * chall.square() + cr * chall_inv.square();
        let round = Round {
            a,
            b,
            basis,
            commitment,
        };
        Ok((round, (cl, cr)))
    }
    fn reduce<S: Duplex<F>>(
        round: Round<F, G>,
        transcript: &mut Transcript<F, S>,
        u: G,
        messages: &mut Vec<(G, G)>,
    ) -> Res<Round<F, G>> {
        if round.reduced() {
            Ok(round)
        } else {
            let (round, (l, r)) = Self::round(round, transcript, u)?;
            messages.push((l, r));
            Self::reduce(round, transcript, u, messages)
        }
    }
    pub fn prove<S: Duplex<F>>(
        &self,
        vectors: [Vec<F>; 2],
        instance: OpenInstance<F, IpaCommitment<G>>,
        transcript: &mut Transcript<F, S>,
    ) -> Res<Proof<F, G>> {
        let [u] = transcript.send_message(&instance)?;
        let OpenInstance {
            commit,
            eval: inner_product,
            ..
        } = instance;
        let u: G::BaseField = cycle_cast(u);
        let u = self.map.map_to_curve(u);
        let commitment = commit.0;
        let commitment: G = commitment + u * inner_product;

        let [a, b] = vectors;
        let basis = self.vector_basis.clone();
        let round = Round {
            a,
            b,
            basis,
            commitment,
        };
        let mut messages = vec![];
        let last_round = Self::reduce(round, transcript, u, &mut messages)?;
        let Round { a, .. } = last_round;
        debug_assert_eq!(a.len(), 1);
        let [] = transcript.send_message(&SingleElement(a[0]))?;
        Ok(Proof { messages, a: a[0] })
    }
    /*pub fn verify<S: Sponge<F, G>>(
        &self,
        sponge: &mut S,
        commitment: G,
        b: Vec<F>,
        inner_product: F,
        proof: Proof<F, G>,
    ) -> bool {
        let Proof { messages, a } = proof;
        sponge.absorb_g(commitment);
        sponge.absorb_f(inner_product);
        let u = sponge.squeeze_g();
        // scaling commitment to prevent shifting
        let commitment: G = commitment + u * inner_product;
        let mut challenges = vec![];
        let commitment: G = messages.into_iter().fold(commitment, |acc, msg| {
            let (cl, cr) = msg;
            sponge.absorb_g(cl);
            sponge.absorb_g(cr);
            let chall = sponge.squeeze_f();
            challenges.push(chall);
            //TODO: batch inverses
            acc + cl * chall.square() + cr * chall.inverse().unwrap().square()
        });
        let mut challs_inv = challenges.clone();
        ark_ff::fields::batch_inversion(&mut challs_inv);

        let s = challenge_combinations(&challenges, &challs_inv);
        let folded_b = compute_inner_product(&s, &b);
        let folded_g = G::msm_unchecked(&self.vector_basis, &s);
        // TODO: zk opening not revealing a
        // Checking that C = aG + abU
        let open = (u * folded_b + folded_g) * a;
        commitment == open
    }*/

    /// Creates SRS from seed for length 2^k for provided k
    pub fn init(len_log: usize, seed: Option<u64>) -> Self {
        let seed = seed.unwrap_or(0);
        let mut rng = StdRng::seed_from_u64(seed);
        let mut point = || G::rand(&mut rng);
        let basis: Vec<G> = std::iter::repeat(())
            .map(|_| point())
            .take(1 << len_log)
            .collect();
        let vector_basis = G::batch_convert_to_mul_base(&basis);
        let map = M::new();
        Self { vector_basis, map }
    }
}

use transcript::{
    messages::{ForeignElement, SingleElement},
    utils::cycle_cast,
    Message, Transcript,
};

use crate::OpenInstance;

struct RoundMsg<G: CurveGroup> {
    cl: G,
    cr: G,
}

type Scalar<G> = <G as Group>::ScalarField;

impl<G: CurveGroup> From<(G, G)> for RoundMsg<G> {
    fn from(value: (G, G)) -> Self {
        let (cl, cr) = value;
        RoundMsg { cl, cr }
    }
}

impl<G: CurveGroup> Message<Scalar<G>> for RoundMsg<G> {
    fn len(vars: usize, param_resolver: &transcript::params::ParamResolver) -> usize {
        ForeignElement::<G::BaseField, Scalar<G>>::len(vars, param_resolver) * 4
    }

    fn to_field_elements(&self) -> Vec<<G as Group>::ScalarField> {
        let [cl, cr] = [self.cl, self.cr].map(G::into_affine);
        let (x1, y1) = cl.xy().unwrap();
        let (x2, y2) = cr.xy().unwrap();
        [x1, y1, x2, y2]
            .into_iter()
            .flat_map(|x| {
                let x: G::BaseField = *x;
                let foreign = ForeignElement::<G::BaseField, Scalar<G>>::from(x);
                foreign.to_field_elements()
            })
            .collect()
    }
}
