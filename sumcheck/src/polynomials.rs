use ark_ff::Field;

///A multilinear extension
#[derive(Clone, Debug)]
pub struct MultilinearPoly<F: Field>(Vec<F>);
///A point with `n` variables
pub struct MultiPoint<F: Field>(Vec<F>);

impl<F: Field> MultiPoint<F> {
    fn pop(mut self) -> (Self, F) {
        let var = self.0.pop().unwrap();
        (self, var)
    }
    fn vars(&self) -> usize {
        self.0.len()
    }
}

impl<F: Field> MultilinearPoly<F> {
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
