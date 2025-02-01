use ark_ff::Field;
use sumcheck::polynomials::MultiPoint;
use transcript::Message;

/// Claim to the evaluation of a matrix in a given point
pub(crate) struct MatrixEvalInstance<F: Field> {
    pub point: [MultiPoint<F>; 2],
    pub eval: F,
}

// TODO: batch in spark
/// Claim to the evaluation of N matrices
pub(crate) struct BatchMatrixEvalInstance<F: Field, const N: usize> {
    pub matrices: [MatrixEvalInstance<F>; N],
}

impl<F: Field> Message<F> for MatrixEvalInstance<F> {
    fn len(vars: usize) -> usize {
        vars * 2 + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        let [x, y] = self.point.clone();
        x.inner()
            .into_iter()
            .chain(y.inner().into_iter())
            .chain([self.eval])
            .collect()
    }
}

impl<F: Field, const N: usize> Message<F> for BatchMatrixEvalInstance<F, N> {
    fn len(vars: usize) -> usize {
        MatrixEvalInstance::<F>::len(vars) * N
    }

    fn to_field_elements(&self) -> Vec<F> {
        self.matrices
            .iter()
            .flat_map(MatrixEvalInstance::<F>::to_field_elements)
            .collect()
    }
}
