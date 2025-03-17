use ark_ff::Field;
use sumcheck::polynomials::MultiPoint;
use transcript::{params::ParamResolver, Message};

pub(crate) struct BatchMatrixEvalInstance<F: Field, const N: usize> {
    pub matrix_evals: [F; N],
    pub point: [MultiPoint<F>; 2],
}

impl<F: Field, const N: usize> Message<F> for BatchMatrixEvalInstance<F, N> {
    fn len(vars: usize, _param_resolver: &ParamResolver) -> usize {
        N + vars * 2
    }

    fn to_field_elements(&self) -> Vec<F> {
        let points = self.point.iter().flat_map(Message::to_field_elements);
        self.matrix_evals.iter().cloned().chain(points).collect()
    }
}
