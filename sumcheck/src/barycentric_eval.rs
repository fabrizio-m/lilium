//! implementation of barycentric evaluation, to evaluate polynomials
//! represented as a set of evaluations without requiring interpolation.
//! O(d^2) once per domain precomputation
//! O(d) cost of evaluation at arbitrary point
//!
//! While any domain could be supported, right now only the inplicit domain
//! 0..d will be used

use ark_ff::{fields::batch_inversion, Field};

/// Weights that can be used to evaluate polynomials defined by
/// n evaluation points over the implicit 0..n domain
pub(crate) struct BarycentricWeights<F: Field> {
    weights: Vec<F>,
    neg_domain: Vec<F>,
}

impl<F: Field> BarycentricWeights<F> {
    /// computes the weights for the inplicit domain 0..n
    pub(crate) fn compute(degree: u32) -> Self {
        let domain: Vec<F> = (0..=degree).map(F::from).collect();
        let neg_domain: Vec<F> = domain.iter().cloned().map(|x| -x).collect();
        let degree = degree as usize;

        let mut weights = Vec::with_capacity(degree + 1);
        for (i, x) in domain[0..=degree].iter().enumerate() {
            let weight = neg_domain
                .iter()
                .enumerate()
                .map(|(j, neg_x)| if i == j { F::one() } else { *neg_x + x })
                .fold(F::one(), |acc, x| acc * x);
            weights.push(weight);
        }
        Self {
            weights,
            neg_domain,
        }
    }
    pub(crate) fn evaluate(&self, evals: &[F], point: F) -> F {
        assert_eq!(self.weights.len(), evals.len());
        let terms: Vec<F> = self.neg_domain.iter().map(|neg_x| *neg_x + point).collect();
        // for the cases where the evaluation point is part of the domain
        for (i, term) in terms.iter().enumerate() {
            if term.is_zero() {
                return evals[i];
            }
        }
        let m = terms.iter().fold(F::one(), |acc, t| acc * t);
        let mut denominators = terms;
        for (d, w) in denominators.iter_mut().zip(&self.weights) {
            *d *= w;
        }
        batch_inversion(&mut denominators);
        let eval = denominators
            .into_iter()
            .zip(evals.iter())
            .fold(F::zero(), |acc, (d, e)| acc + d * e);
        m * eval
    }
}

#[cfg(test)]
mod tests {
    use super::BarycentricWeights;
    use ark_ff::Field;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_vesta::Fr;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_barycentric_eval() {
        let evals = 16;
        let degree = evals - 1;
        let weights = BarycentricWeights::<Fr>::compute(degree);

        let mut rng = thread_rng();
        for _ in 0..16 {
            let poly = DensePolynomial::<Fr>::rand(degree as usize, &mut rng);
            let bytes: [u8; 30] = rng.gen();
            let point = Fr::from_random_bytes(&bytes).unwrap();
            let true_eval = poly.evaluate(&point);

            let evals: Vec<Fr> = (0..evals).map(|i| poly.evaluate(&Fr::from(i))).collect();
            let check_eval = weights.evaluate(&evals, point);
            assert_eq!(true_eval, check_eval);
            let eval1 = evals[1];
            let check_eval = weights.evaluate(&evals, Fr::from(1));
            assert_eq!(eval1, check_eval);
        }
    }
}
