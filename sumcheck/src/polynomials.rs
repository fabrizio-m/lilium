use ark_ff::Field;
use std::ops::Index;

///A point with `n` variables
#[derive(Clone)]
pub struct MultiPoint<F: Field>(Vec<F>);

impl<F: Field> MultiPoint<F> {
    pub fn new(vars: Vec<F>) -> Self {
        MultiPoint(vars)
    }
    pub(crate) fn pop(mut self) -> (Self, F) {
        let var = self.0.pop().unwrap();
        (self, var)
    }
    pub(crate) fn pop_mut(&mut self) -> F {
        self.0.pop().unwrap()
    }
    pub fn vars(&self) -> usize {
        self.0.len()
    }
    pub fn inner(self) -> Vec<F> {
        self.0
    }
}

/// must be some wrapper over [F], representing all the evaluations at some
/// point of the domain
pub trait Evals<F: Field>: Index<Self::Idx, Output = F> {
    type Idx: Copy;
    ///should combine 2 [Self] into one by using `f` to combine each element
    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self;
}

pub trait EvalsExt<F: Field>: Evals<F> + Sized {
    fn fix_var(mut mle: Vec<Self>, var: F) -> Vec<Self> {
        let half_len = mle.len() / 2;
        let one_minus_var = F::one() - var;
        let (left, right) = mle.split_at_mut(half_len);

        let f = |a, b| one_minus_var * a + var * b;
        for (left, right) in left.iter_mut().zip(right) {
            let left: &mut Self = left;
            let comb = left.combine(right, f);
            *left = comb;
        }
        mle.truncate(half_len);
        mle
    }
    fn eval(mle: Vec<Self>, point: MultiPoint<F>) -> Self {
        assert_eq!(
            mle.len().ilog2() as usize,
            point.vars(),
            "number of variables missmatch"
        );
        let (point, var) = point.pop();
        let mle = Self::fix_var(mle, var);
        if point.vars() == 0 {
            mle.into_iter().next().unwrap()
        } else {
            Self::eval(mle, point)
        }
    }
}
impl<F, T> EvalsExt<F> for T
where
    T: Evals<F> + Sized,
    F: Field,
{
}

pub struct SingleEval<F>(pub F);
impl<F> Index<()> for SingleEval<F> {
    type Output = F;

    fn index(&self, _index: ()) -> &Self::Output {
        &self.0
    }
}

impl<F: Field> Evals<F> for SingleEval<F> {
    type Idx = ();

    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
        SingleEval(f(self.0, other.0))
    }
}

pub mod simple_eval {
    use super::Evals;
    use crate::utils::ZeroCheckAvailable;
    use ark_ff::Field;
    use std::ops::Index;

    #[derive(Clone, Debug)]
    pub struct SimpleEval<F, const N: usize>([F; N]);

    impl<F, const N: usize> SimpleEval<F, N> {
        pub fn new(inner: [F; N]) -> Self {
            Self(inner)
        }
    }
    impl ZeroCheckAvailable for usize {
        fn zerocheck_eq() -> Self {
            0
        }
    }

    impl<F: Field, const N: usize> Index<usize> for SimpleEval<F, N> {
        type Output = F;

        fn index(&self, index: usize) -> &Self::Output {
            &self.0[index]
        }
    }
    impl<F: Field, const N: usize> Evals<F> for SimpleEval<F, N> {
        type Idx = usize;

        fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
            let mut res = self.0.clone();
            for i in 0..N {
                res[i] = f(res[i], other.0[i]);
            }
            Self(res)
        }
    }
}
