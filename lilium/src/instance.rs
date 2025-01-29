use ark_ff::Field;
use commit::CommmitmentScheme;
use sumcheck::polynomials::MultiPoint;
use transcript::Message;

struct Instance<F: Field, C: CommmitmentScheme<F>, const I: usize> {
    witness_commit: C::Commitment,
    public_inputs: [F; I],
}
pub(crate) struct LinearizedInstance<
    F: Field,
    C: CommmitmentScheme<F>,
    const I: usize,
    const IO: usize,
> {
    witness_commit: C::Commitment,
    /// first element of the vector to be multiplied with the matrices, formed
    /// by this, the public inputs and the witness. It's 1 in trivial cases.
    u: F,
    public_inputs: [F; I],
    /// the sum of the resulting vector from each matrix multiplication
    matrix_evals: [F; IO],
}

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
