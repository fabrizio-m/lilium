use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use sponge::Sponge;
use vector_utils::{challenge_combinations, compute_inner_product, fold_basis, fold_vec};

mod sponge;
#[cfg(test)]
mod tests;
mod vector_utils;

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

pub struct IpaScheme<F, G>
where
    F: Field,
    G: VariableBaseMSM<ScalarField = F>,
{
    // basis to commit to the non-public vector
    vector_basis: Vec<G::MulBase>,
}

pub struct Round<F, G: VariableBaseMSM<ScalarField = F>> {
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

pub struct Proof<F, G> {
    messages: Vec<(G, G)>,
    a: F,
}

impl<F, G> IpaScheme<F, G>
where
    F: Field,
    G: VariableBaseMSM<ScalarField = F>,
{
    pub fn new(vector_basis: Vec<G::MulBase>) -> Self {
        Self { vector_basis }
    }

    pub fn round<S: Sponge<F, G>>(
        round: Round<F, G>,
        sponge: &mut S,
        product_base: G,
    ) -> (Round<F, G>, (G, G)) {
        let Round {
            a,
            b,
            basis,
            commitment,
        } = round;
        let [cl, cr] = ipa_reduce::<F, G>([&a, &b], &basis, product_base);
        sponge.absorb_g(cl);
        sponge.absorb_g(cr);
        let chall = sponge.squeeze_f();
        let chall_inv = chall.inverse().unwrap();
        let a = fold_vec(a, [chall, chall_inv]);
        let b = fold_vec(b, [chall_inv, chall]);
        let basis = fold_basis::<G>(basis, [chall, chall_inv]);
        let commitment = commitment + cl * chall.square() + cr * chall_inv.square();
        let round = Round {
            a,
            b,
            basis,
            commitment,
        };
        (round, (cl, cr))
    }
    pub fn reduce<S: Sponge<F, G>>(
        round: Round<F, G>,
        sponge: &mut S,
        u: G,
        messages: &mut Vec<(G, G)>,
    ) -> Round<F, G> {
        if round.reduced() {
            round
        } else {
            let (round, (l, r)) = Self::round(round, sponge, u);
            messages.push((l, r));
            Self::reduce(round, sponge, u, messages)
        }
    }
    pub fn prove<S: Sponge<F, G>>(
        &self,
        vectors: [Vec<F>; 2],
        inner_product: Option<F>,
        commitment: G,
        sponge: &mut S,
    ) -> Proof<F, G> {
        // TODO: compute
        let inner_product = inner_product.unwrap();
        sponge.absorb_g(commitment);
        sponge.absorb_f(inner_product);
        let u = sponge.squeeze_g();
        // scaling commitment to prevent shifting
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
        let last_round = Self::reduce(round, sponge, u, &mut messages);
        let Round { a, .. } = last_round;
        debug_assert_eq!(a.len(), 1);
        Proof { messages, a: a[0] }
    }
    pub fn verify<S: Sponge<F, G>>(
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
    }
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
        Self { vector_basis }
    }
}
