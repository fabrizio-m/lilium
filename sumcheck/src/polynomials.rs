use ark_ff::Field;
use std::ops::Index;

///A point with `n` variables
pub struct MultiPoint<F: Field>(Vec<F>);

impl<F: Field> MultiPoint<F> {
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
}

/// must be some wrapper over [F], representing all the evaluations at some
/// point of the domain
pub trait Evals<F: Field>: Index<Self::Idx, Output = F> {
    type Idx: Copy;
    ///should combine 2 [Self] into one by using `f` to combine each element
    fn combine<C: Fn(F, F) -> F>(&mut self, other: &Self, f: C) -> Self;
}

pub trait EvalsExt<F: Field>: Evals<F> + Sized {
    fn fix_var(mut mle: Vec<Self>, var: F) -> Vec<Self> {
        let half_len = mle.len() / 2;
        let one_minus_var = F::one() - var;
        let (left, right) = mle.split_at_mut(half_len);

        let f = |a, b| one_minus_var * a + var * b;
        for (left, right) in left.iter_mut().zip(right) {
            let left: &mut Self = left;
            left.combine(right, f);
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

/*impl<F: Field> MultilinearPoly<F> {
    fn new(extension: Vec<F>) -> Self {
        assert!(extension.len().is_power_of_two(), "len must be power of 2");
        MultilinearPoly(extension)
    }
    fn eval(&self, point: MultiPoint<F>) -> F {
        assert_eq!(
            self.0.len().ilog2(),
            point.0.len() as u32,
            "mismatch in number of variables between point and MLE"
        );
        self.clone().eval_rec(point)
    }
    ///fixes one varible, returning an mle and point with one less variables
    fn fix_var(self, point: MultiPoint<F>) -> (Self, MultiPoint<F>) {
        let (point, var) = point.pop();
        let mut mle = self.0;
        let mle_half_len = mle.len() / 2;
        let one_minus_var = F::one() - var;
        let (left, right) = mle.split_at_mut(mle_half_len);

        for (left, right) in left.iter_mut().zip(right) {
            *left = one_minus_var * (*left) + var * right;
        }
        mle.truncate(mle_half_len);
        (Self(mle), point)
    }
    fn eval_rec(self, point: MultiPoint<F>) -> F {
        if point.vars() == 1 {
            let (eval, _) = self.fix_var(point);
            eval.0[0]
        } else {
            let (mle, point) = self.fix_var(point);
            mle.eval_rec(point)
        }
    }
}
*/
