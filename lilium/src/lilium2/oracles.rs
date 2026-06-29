use ark_ff::Field;
use ccs::matrix::Matrix;
use commit::commit2::CommitmentScheme;
use std::{marker::PhantomData, ops::Add, rc::Rc};
use sumcheck::{
    polynomials::MultiPoint,
    sumcheck2::{
        evals::EvalsCore,
        oracles::{
            partial::{Nature, OracleEval, OracleParams, PartialOracle, PartialQueryInstance},
            EvalLocation, SumcheckFunction,
        },
    },
};
use transcript::reduction2::{Message, NoError, Relation};

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct MatrixProductOracle<F, SF, C, const N: usize>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    matrices: [Rc<Matrix>; N],
    vector: SF::Mles<bool>,
    pcs: C,
    _f: PhantomData<F>,
}

#[derive(Clone, Copy, Debug)]
struct MatrixProductInstance<F: Field, C: CommitmentScheme<F>> {
    /// The commitment to z(x) for each z*M_i(x).
    committment: C::Commitment,
}

impl<F: Field, C: CommitmentScheme<F>> Message<F> for MatrixProductInstance<F, C> {
    type Params = OracleParams;

    type Error = NoError;

    fn len(_: &Self::Params) -> usize {
        C::Commitment::len(&())
    }

    fn to_field_elements(&self, _: &Self::Params) -> Result<Vec<F>, Self::Error> {
        self.committment.to_field_elements(&())
    }
}

#[derive(Clone, Copy, Debug)]
struct MatrixNature;

impl Nature for MatrixNature {}

impl From<MatrixNature> for EvalLocation {
    fn from(_: MatrixNature) -> Self {
        EvalLocation::Structure
    }
}

impl<F, SF, C, const N: usize> PartialOracle<F, SF> for MatrixProductOracle<F, SF, C, N>
where
    F: Field,
    SF: SumcheckFunction<F>,
    C: CommitmentScheme<F>,
    SF::Natures: Nature,
{
    type Instance = MatrixProductInstance<F, C>;

    type VerifierKey = Self;

    type Builder = Self;

    type Nature = MatrixNature;

    type QueryRelation = MatrixOracleQuery<F, SF, C, N>;

    fn build(builder: Self, _: &SF, _: Rc<Vec<<SF>::Mles<F>>>) -> Self {
        builder
    }

    fn instance_evals(_: &Self::Instance) -> <SF>::Mles<F> {
        SF::map_evals(&SF::natures(), |_| F::ZERO)
    }

    fn evals(
        _key: &Self::VerifierKey,
        _instance: &Self::Instance,
        _point: &MultiPoint<F>,
    ) -> <SF>::Mles<OracleEval<F>> {
        let natures = SF::natures();

        SF::map_evals(&natures, |nature| {
            let nature: Option<MatrixNature> = nature.into_dynamic().into();
            match nature {
                Some(MatrixNature) => OracleEval::ProverProvided,
                None => OracleEval::None,
            }
        })
    }

    fn prover_provided(_: &Self::Nature) -> bool {
        true
    }
}

struct MatrixOracleQuery<F, SF, C, const N: usize>(PhantomData<(F, SF, C)>);

impl<F, SF, C, const N: usize> Relation for MatrixOracleQuery<F, SF, C, N>
where
    F: Field,
    SF: SumcheckFunction<F>,
    C: CommitmentScheme<F>,
    SF::Natures: Nature,
{
    type Structure = MatrixProductOracle<F, SF, C, N>;

    type Instance = PartialQueryInstance<F, MatrixProductInstance<F, C>>;

    type Witness = Vec<SF::Mles<F>>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let vector_count = structure
            .vector
            .clone()
            .flatten_vec()
            .into_iter()
            .fold(0, |acc, x| if x { acc + 1 } else { acc });

        if vector_count != 1 {
            return false;
        }

        let vector = {
            let mut vector = vec![];
            let vector_filter = &structure.vector;
            for witness in witness {
                let filtered =
                    SF::combine(witness, vector_filter, |w, f| if *f { *w } else { F::ZERO });
                vector.push(filtered.flatten_vec().into_iter().fold(F::ZERO, Add::add));
            }
            vector
        };

        let matrix_indices: SF::Mles<Option<usize>> = {
            let mut next = 0;
            let indices = SF::natures()
                .flatten_vec()
                .into_iter()
                .map(|nature| {
                    let nature = nature.into_dynamic().into();
                    nature.map(|_: MatrixNature| {
                        next += 1;
                        next - 1
                    })
                })
                .collect();
            if next != N {
                return false;
            }
            SF::Mles::unflatten_vec(indices)
        };

        for (i, matrix) in structure.matrices.iter().enumerate() {
            let product = matrix.as_ref() * vector.as_slice();
            assert_eq!(product.len(), witness.len());

            for (product, witness) in product.into_iter().zip(witness) {
                let expected = SF::combine(&matrix_indices, witness, |index, witness| {
                    index
                        .map(|index| if index == i { Some(*witness) } else { None })
                        .flatten()
                });
                let expected = expected
                    .flatten_vec()
                    .into_iter()
                    .fold(None, |acc, e| acc.xor(e));

                if product != expected.unwrap() {
                    return false;
                }
            }
        }

        let MatrixProductInstance { committment } = instance.oracle_instance();
        *committment == structure.pcs.commit_mle(&vector)
    }
}
