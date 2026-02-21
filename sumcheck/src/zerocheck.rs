//! Utilities for zerocheck.

use crate::polynomials::MultiPoint;
use ark_ff::Field;
use std::iter::successors;

/// Multilinear polynomial of form:
/// p(x_0) = x_0 * ß + (1 - x_0) * c
/// p(x_{i+1}) = x_{i+1} * ß^{2^i} * p(x_i)
/// For some challenge ß and c = 1.
/// Making the MLE essentially a vector
/// 1, ß, ß^2, .. , ß^{2^k}
/// Represented as a product of degree 1 univariate polynomials.
/// For v varibles, point evaluation if O(v) and MLE computation is
/// O(2^v).
pub struct CompactPowers<F: Field> {
    coefficients: Vec<(F, F)>,
}

impl<F: Field> CompactPowers<F> {
    pub fn new(chall: F, vars: usize) -> Self {
        let coefficients = successors(Some(chall), |last| Some(last.square()))
            .map(|c| (c, F::one()))
            .take(vars)
            .collect();
        Self { coefficients }
    }

    pub fn point_eval(&self, point: &MultiPoint<F>) -> F {
        assert_eq!(self.coefficients.len(), point.vars());

        self.coefficients
            .iter()
            .zip(point.inner_ref())
            .fold(F::one(), |acc, ((b, c), x)| {
                acc * (*x * b + (F::one() - x) * c)
            })
    }

    pub fn eval_over_domain(&self) -> Vec<F> {
        let vars = self.coefficients.len();

        // p(x) = 0 * ß + (1 - 0) * c = c
        let eval_at_zero = self
            .coefficients
            .iter()
            .fold(F::one(), |acc, (_, c)| acc * c);

        // Multiplying each of these has the effect of swaping the corresponding
        // from 0 to 1.
        // For example: e(0,0,0,0) * f0 * f2 = e(1,0,1,0).
        let mut flips: Vec<F> = self
            .coefficients
            .iter()
            .map(|(b, c)| c.inverse().unwrap() * b)
            .collect();
        // as write_evals() recurses in the reverse order.
        flips.reverse();

        let mut mle = vec![F::zero(); 1 << vars];
        mle[0] = eval_at_zero;
        mle[1] = eval_at_zero;

        write_evals(&mut mle, &flips);
        mle
    }
}

/// Unlike `crate::eq`, the base case expects dest to contain the
/// evaluation at 0 already.
fn write_evals<F: Field>(dest: &mut [F], flips: &[F]) {
    assert!(dest.len().is_power_of_two());
    if flips.len() == 1 {
        assert_eq!(dest.len(), 2);
        dest[1] *= flips[0];
    } else {
        let var = flips[0];
        let (left, right) = dest.split_at_mut(dest.len() / 2);
        assert_eq!(left.len(), right.len());
        write_evals(left, &flips[1..]);
        for (l, r) in left.iter().zip(right.iter_mut()) {
            *r = *l * var;
        }
    }
}

fn test<F: Field>(chall: F) {
    let vars = 5;
    let powers = CompactPowers::new(chall, vars);
    assert_eq!(
        powers.point_eval(&MultiPoint::new(vec![F::zero(); vars])),
        F::one()
    );
    let powers = powers.eval_over_domain();
    assert_eq!(powers.len(), 1 << vars);
    let mut expected = F::one();
    for eval in powers {
        assert_eq!(eval, expected);
        expected *= chall;
    }
}

#[test]
fn compact_powers() {
    use ark_ff::UniformRand;
    use ark_vesta::Fr;
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(0);
    let chall = Fr::rand(&mut rng);
    test(chall);
}

// Wrapper over functions that may be worth implementing in the future.
/*
struct ZeroCheck<F: Field, SF: SumcheckFunction<F>> {
    f: SF,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
enum Idx<I> {
    ZeroCheckChallenge,
    Inner(I),
}

#[derive(Clone, Debug)]
struct ZeroCheckMles<V, I> {
    challenge: V,
    inner: I,
}

impl<V: Copy, I: Evals<V>> Evals<V> for ZeroCheckMles<V, I> {
    type Idx = Idx<I::Idx>;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            Idx::ZeroCheckChallenge => &self.challenge,
            Idx::Inner(idx) => self.inner.index(idx),
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let challenge = f(self.challenge, other.challenge);
        let inner = self.inner.combine(&other.inner, f);
        ZeroCheckMles { challenge, inner }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self { challenge, inner } = self;
        vec.push(challenge);
        inner.flatten(vec);
    }

    fn unflatten(elems: &mut IntoIter<V>) -> Self {
        let challenge = elems.next().unwrap();
        let inner = I::unflatten(elems);
        Self { challenge, inner }
    }
}

const fn kinds<I>(inner: I) -> ZeroCheckMles<EvalKind, I> {
    ZeroCheckMles {
        challenge: EvalKind::FixedSmall,
        inner,
    }
}

impl<F: Field, SF: SumcheckFunction<F>> SumcheckFunction<F> for ZeroCheck<F, SF> {
    type Idx = Idx<SF::Idx>;

    type Mles<V: Copy + Debug> = ZeroCheckMles<V, SF::Mles<V>>;
    // type Mles<V: Copy + Debug> = ;

    type Challs = SF::Challs;

    type ChallIdx = SF::ChallIdx;

    const KINDS: Self::Mles<EvalKind> = kinds(SF::KINDS);

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        let ZeroCheckMles { challenge, inner } = evals;
        let challenge = f(challenge);
        let inner = SF::map_evals(inner, f);
        ZeroCheckMles { challenge, inner }
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(env: E) -> V {
        let chall = env.get(Idx::ZeroCheckChallenge);
    }
}
*/
