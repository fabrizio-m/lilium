use crate::{
    barycentric_eval::BarycentricWeights,
    folding::{
        prover::SumFoldProverOutput, utils::FieldFolder, SumFold, SumFoldInstance, SumFoldProof,
    },
    message::Message,
    polynomials::Evals,
    sumcheck::{Sum, SumcheckFunction, SumcheckProver},
    symbolic::sumcheck_eval::SumcheckEvaluator,
    zerocheck::CompactPowers,
};
use ark_ff::Field;
use rayon::ThreadPoolBuilder;
use sponge::sponge::Duplex;
use transcript::Transcript;

/// Speciallized `SumFold` prover for zerocheck, verification remains
/// as usual through `SumFold`, available at `ZeroFold::sumfold_key`.
/// The main difference is that the message size increases by 1 for each
/// variable, but the impact of such higher degree sumcheck in the prover
/// is minimal.
pub struct ZeroFold<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    sumfold: SumFold<F, SF>,
    /// Weights to interpolate polynomials of degrees between degree(SF) and
    /// degree(SF) + vars.
    weights: Vec<BarycentricWeights<F>>,
}

impl<F, SF> ZeroFold<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    pub fn new(f: SF, vars: usize) -> Self {
        let degree = SumcheckProver::<F, SF>::degree_symbolic(&f);
        let sumfold = SumFold::new_custom_degree(degree + vars, &f);
        let weights = (0..vars)
            .map(|i| BarycentricWeights::compute((degree + i) as u32))
            .collect();
        Self { sumfold, weights }
    }

    pub fn sumfold_key(&self) -> &SumFold<F, SF> {
        &self.sumfold
    }

    /// Same as `SumFold::fold`, speciallized to efficiely handle the particularities
    /// of zerocheck.
    pub fn fold_zerocheck<S>(
        &self,
        w1: Vec<SF::Mles<F>>,
        w2: &[SF::Mles<F>],
        sums: Option<SumFoldInstance<F, 2>>,
        powers: [CompactPowers<F>; 2],
        challenges: SF::Challs,
        transcript: &mut Transcript<F, S>,
    ) -> SumFoldProverOutput<F, SF>
    where
        S: Duplex<F>,
    {
        assert_eq!(w1.len(), w2.len());
        let mut w1 = w1;

        let pool = ThreadPoolBuilder::new().build().unwrap();
        let message = pool.install(|| self.sum_messages(&w1, w2, powers, challenges));

        // Check against sums if provided.
        let instance = if let Some(sums) = sums {
            assert_eq!(sums.sums[0].0, message.eval_at_0());
            assert_eq!(sums.sums[1].0, message.eval_at_1());
            sums
        } else {
            SumFoldInstance {
                sums: [message.eval_at_0(), message.eval_at_1()].map(Sum),
            }
        };

        // Lock instance an generate challenge.
        let [beta] = transcript.send_message(&instance).unwrap();

        let eq_beta = Message::new_degree_n(F::one() - beta, beta, self.sumfold.degree + 1);
        // Compute final message eq(beta,x) * f(x).
        // By doing it at the end, having to compute d+2 points in the whole hypercube is
        // avoided, it is done instead over d+1 points.
        // For that same reason the original message has to be extended to d+2 points.
        let message = {
            let extended = message.clone().extend(&self.sumfold.weights);
            extended * eq_beta
        };
        // Message is sent and sumcheck challenge received.
        let [r] = transcript.send_message(&message).unwrap();

        // Checking that message agrees with sum.
        {
            let sum = instance.sums[0].0 * (F::ONE - beta) + instance.sums[1].0 * beta;
            let eval_zero = message.eval_at_0();
            let eval_one = message.eval_at_1();
            assert_eq!(sum, eval_zero + eval_one);
        };

        let sum = {
            let sum = message.eval_at_x(r, &self.sumfold.extended_weights);
            let eqr = r * beta + (F::one() - r) * (F::one() - beta);
            sum / eqr
        };

        let proof = SumFoldProof { message };

        // Witness is folded as expected from the sumcheck reduction.
        for (e1, e2) in w1.iter_mut().zip(w2.iter()) {
            let folded = e1.combine(e2, |e1, e2| e1 * (F::ONE - r) + e2 * r);
            *e1 = folded;
        }
        let folded_witness = w1;

        let folder = FieldFolder::new(r);

        SumFoldProverOutput {
            instance,
            folded_witness,
            proof,
            folder,
            sum,
        }
    }

    fn sum_messages(
        &self,
        w1: &[SF::Mles<F>],
        w2: &[SF::Mles<F>],
        powers: [CompactPowers<F>; 2],
        challenges: SF::Challs,
    ) -> Message<F> {
        let evaluator = self.sumfold.evaluator.clone();

        let base_weights = &self.weights[0];
        let mut messages = vec![F::ZERO; w1.len() * base_weights.domain_size()];

        Self::sum_par(
            w1,
            w2,
            &challenges,
            &mut messages,
            &evaluator,
            base_weights.domain_size() - 1,
        );

        let powers_left = powers[0].factors();
        let powers_right = powers[1].factors();
        // Repeat with the rest of variables until a single message is left.
        let (powers, weights): (Vec<_>, Vec<_>) = powers_left
            .iter()
            .zip(powers_right)
            .zip(&self.weights)
            .map(|(powers, weights)| {
                let degree = weights.domain_size() - 1;
                let (powers_left, powers_right) = powers;
                let powers_even = [powers_left.1, powers_right.1];
                let powers_odd = [powers_left.0, powers_right.0];
                let powers = [powers_even, powers_odd].map(|powers| {
                    let [e0, e1] = powers;
                    Message::new_degree_n(e0, e1, degree + 1)
                });
                (powers, weights.clone())
            })
            .rev()
            .unzip();

        let degree = weights[0].domain_size();

        Self::fold_with_powers_rec(&mut messages, &powers, &weights, degree);

        let message = messages[0..=degree].to_vec();

        assert_eq!(
            message.len(),
            self.weights.last().unwrap().domain_size() + 1
        );
        Message::new(message)
    }

    fn sum_par(
        w1: &[SF::Mles<F>],
        w2: &[SF::Mles<F>],
        challenges: &SF::Challs,
        out: &mut [F],
        evaluator: &SumcheckEvaluator<F, SF>,
        degree: usize,
    ) {
        assert!(w1.len().is_power_of_two());
        assert_eq!(w1.len(), w2.len());
        assert_eq!(w1.len() * (degree + 1), out.len());
        let len = w1.len();
        if len > 512 {
            let (w1l, w1r) = w1.split_at(len / 2);
            let (w2l, w2r) = w1.split_at(len / 2);
            let (out_l, out_r) = out.split_at_mut(out.len() / 2);

            let fl = || Self::sum_par(w1l, w2l, challenges, out_l, evaluator, degree);
            let fr = || Self::sum_par(w1r, w2r, challenges, out_r, evaluator, degree);
            rayon::join(fl, fr);
        } else {
            let [mut ev1, mut ev2] = [evaluator.clone(), evaluator.clone()];
            // let mut accumulator = evaluator.accumulator(challenges);
            let mut acc1 = ev1.accumulator(challenges);
            let mut acc2 = ev2.accumulator(challenges);

            for i in 0..(len / 2) {
                let evals = [&w1[i * 2], &w2[i * 2]];
                // let res0 = accumulator.eval_and_zero(evals);
                let res0 = acc1.zero_and_eval(evals);
                let evals = [&w1[i * 2 + 1], &w2[i * 2 + 1]];
                let res1 = acc2.zero_and_eval(evals);
                for j in 0..res0.len() {
                    out[i * (degree + 1) + j] = res0[j];
                    out[(i + 1) * (degree + 1) + j] = res1[j];
                }
            }
        }
    }

    fn fold_with_powers_rec(
        messages: &mut [F],
        powers: &[[Message<F>; 2]],
        weights: &[BarycentricWeights<F>],
        degree: usize,
    ) {
        assert_eq!(weights.len(), powers.len());
        assert!(
            messages.len() > degree,
            "m:{}, deg: {}",
            messages.len(),
            degree
        );
        if messages.len() == (degree + 1) {
            // Do nothing.
            debug_assert!(weights.is_empty());
            debug_assert!(powers.is_empty());
            debug_assert_eq!(messages.len(), degree + 1);
        } else {
            let (l, r) = messages.split_at_mut(messages.len() / 2);

            match powers.len() {
                0 => {
                    Self::fold_with_powers_rec(l, powers, weights, degree - 1);
                    Self::fold_with_powers_rec(r, powers, weights, degree - 1);
                }
                1..=9 => {
                    Self::fold_with_powers_rec(l, &powers[1..], &weights[1..], degree - 1);
                    Self::fold_with_powers_rec(r, &powers[1..], &weights[1..], degree - 1);
                }
                _ => {
                    let ((), ()) = rayon::join(
                        || Self::fold_with_powers_rec(l, &powers[1..], &weights[1..], degree - 1),
                        || Self::fold_with_powers_rec(r, &powers[1..], &weights[1..], degree - 1),
                    );
                }
            }
            let [powers_l, powers_r] = &powers[0];
            let powers_l = powers_l.inner();
            let powers_r = powers_r.inner();
            let exl = weights[0].extend(&l[0..degree]);

            let exr = weights[0].extend(&r[0..degree]);
            for i in 0..degree {
                l[i] = powers_l[i] * l[i] + powers_r[i] * r[i];
            }
            messages[degree] = powers_l[degree] * exl + powers_r[degree] * exr;
        }
    }

    #[allow(dead_code)]
    fn fold_with_powers(
        powers: [[F; 2]; 2],
        messages: Vec<F>,
        weights: &BarycentricWeights<F>,
    ) -> Vec<F> {
        let [powers_even, powers_odd] = powers;
        // As domain_size = degree + 1.
        let powers_degree = weights.domain_size();
        let powers_even = Message::new_degree_n(powers_even[0], powers_even[1], powers_degree - 1);
        let powers_even = powers_even.inner();
        let powers_even_last = weights.extend(powers_even);
        let powers_odd = Message::new_degree_n(powers_odd[0], powers_odd[1], powers_degree - 1);
        let powers_odd = powers_odd.inner();
        let powers_odd_last = weights.extend(powers_odd);
        assert_eq!(messages.len() % weights.domain_size(), 0);
        let n = messages.len() / weights.domain_size();

        let mut res = vec![];

        for i in 0..(n / 2) {
            let size = weights.domain_size();
            let offset = i * size * 2;
            let messages = &messages[offset..offset + size * 2];
            let (msg0, msg1) = messages.split_at(size);
            for i in 0..msg0.len() {
                let even = msg0[i] * powers_even[i];
                let odd = msg1[i] * powers_odd[i];
                res.push(even + odd);
            }
            let msg0 = weights.extend(msg0);
            let msg1 = weights.extend(msg1);
            res.push(msg0 * powers_even_last + msg1 * powers_odd_last);
        }
        assert_eq!(res.len(), (n / 2) * (weights.domain_size() + 1));
        res
    }
}
