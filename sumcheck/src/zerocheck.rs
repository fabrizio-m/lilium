//! Utilities for zerocheck.

use crate::polynomials::MultiPoint;
use ark_ff::Field;
use std::{
    iter::successors,
    ops::{Add, Mul},
};

/// Multilinear polynomial of form:
/// p(x_0) = x_0 * ß + (1 - x_0) * c
/// p(x_{i+1}) = (x_{i+1} * ß^{2^i} + (1 - x_i) * c_i) * p(x_i)
/// For some challenge ß and c = 1.
/// Making the MLE essentially a vector
/// 1, ß, ß^2, .. , ß^{2^k}
/// Represented as a product of degree 1 univariate polynomials.
/// For v varibles, point evaluation if O(v) and MLE computation is
/// O(2^v).
#[derive(Clone, Debug)]
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

#[cfg(test)]
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

impl<F: Field> Mul<F> for CompactPowers<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self::Output {
        for (b, c) in self.coefficients.iter_mut() {
            *b *= rhs;
            *c *= rhs;
        }
        self
    }
}

impl<F: Field> Add<Self> for CompactPowers<F> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        for (l, r) in self.coefficients.iter_mut().zip(rhs.coefficients) {
            l.0 += r.0;
            l.1 += r.1;
        }
        self
    }
}

#[cfg(test)]
fn bits(x: usize, left: usize) -> Vec<u8> {
    match left {
        0 => {
            vec![]
        }
        left => {
            let bit = x & 0b1;
            let mut tail = bits(x >> 1, left - 1);
            tail.push(bit as u8);
            tail
        }
    }
}

#[cfg(test)]
fn compact_powers_over_domain<F: Field>(challs: [F; 3]) {
    let vars = 5;
    let [c1, c2, c3] = challs;
    let powers1 = CompactPowers::new(c1, vars);
    let powers2 = CompactPowers::new(c2, vars);
    let powers3 = powers1.clone() * c3 + powers2.clone();

    let mut evals3 = powers3.eval_over_domain().into_iter();
    for i in 0..(1 << vars) {
        let point = bits(i, vars).into_iter().map(F::from);
        let point = MultiPoint::new(point.rev().collect());
        let e3 = evals3.next().unwrap();
        assert_eq!(e3, powers3.point_eval(&point));
    }
}

#[test]
fn powers_over_domain() {
    use ark_ff::UniformRand;
    use ark_vesta::Fr;
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(0);
    let mut chall = || Fr::rand(&mut rng);

    let challs = [(); 3].map(|_| chall());
    compact_powers_over_domain(challs);
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

// e1 = [1,ß], e2 = [1,ß^2]
// e(0,0) = e1(0) * e2(o) = 1 * 1   = 1
// e(1,0) = e1(1) * e2(o) = ß * 1   = ß
// e(0,1) = e1(0) * e2(1) = 1 * ß^2 = ß^2
// e(1,1) = e1(1) * e2(1) = ß * ß^2 = ß^3
// e1' = α*e1, e2' = α*e2
// e'(0,0) = e1'(0) * e2'(o) = α * α     = α^2
// e'(1,0) = e1'(1) * e2'(o) = ßα * α    = ßα^2
// e'(0,1) = e1'(0) * e2'(1) = α * ß^2α  = ß^2α^2
// e'(1,1) = e1'(1) * e2'(1) = ßα * ß^2α = ß^3α^2
// e1'' = α*e1, e2'' = e2
// e''(0,0) = e1''(0) * e2''(o) = α * 1  = α
// e''(1,0) = e1''(1) * e2''(o) = ßα * 1 = ßα
// e''(0,1) = e1''(0) * e2''(1) = α * ß^2 = ß^2α
// e''(1,1) = e1''(1) * e2''(1) = ßα * ß^2 = ß^3α
//
//
// e1 = [1,ß], e2 = [1,ß^2]
// e1 * α + e1 = [α + 1, ßα   + ß]
// e2 * α + e2 = [α + 1, ß^2α + ß^2]
// e(0,0) = e1(0) * e2(o) = α + 1 * α + 1 = 1
