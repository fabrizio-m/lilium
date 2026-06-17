use crate::barycentric_eval::BarycentricWeights;
use crate::sumcheck2::SumcheckMessage;
use ark_ff::Field;
use std::ops::Mul;

impl<F: Field> SumcheckMessage<F> {
    pub fn zero(degree: usize) -> Self {
        Self(vec![F::ZERO; degree + 1])
    }

    pub(crate) fn new_degree_n(eval_at_0: F, eval_at_1: F, degree: usize) -> Self {
        assert!(degree >= 1, "degree should be >= 1");
        // e0, e1
        // P(x) = (e1 - e0)x + e0
        // TODO: it may be possible to exploit this structure further
        let mut message = Vec::with_capacity(degree + 1);
        let diff = eval_at_1 - eval_at_0;
        let mut last = F::zero();
        //as x is 0..d multiplication is unnecessary
        for _ in 0..=degree {
            message.push(last + eval_at_0);
            last += diff;
        }
        Self(message)
    }

    /// Adds an extra evaluation to handle a bigger degree.
    pub(crate) fn extend(self, weights: &BarycentricWeights<F>) -> Self {
        assert_eq!(self.0.len(), weights.domain_size());
        // The message length equals the weights length, so the next point is the constant
        // out-of-domain point that weights.extend(...) has already been precomputed for
        let message_extra_eval = weights.extend(&self.0);
        let evals = self.0.into_iter().chain([message_extra_eval]);
        Self(evals.collect())
    }
}

impl<F: Field> Mul for SumcheckMessage<F> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        for ab in self.0.iter_mut().zip(rhs.0.iter()) {
            let (a, b): (&mut F, &F) = ab;
            *a *= b;
        }
        self
    }
}
