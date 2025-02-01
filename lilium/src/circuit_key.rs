use ark_ff::Field;
use ccs::{
    circuit::{BuildStructure, Circuit},
    structure::{CcsStructure, Matrix},
};
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use spark::{
    challenges::SparkChallenges, evals::SparkEval, spark::SparkEvalCheck, structure::SparkMatrix,
};
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use sumcheck::polynomials::MultiPoint;
use transcript::{TranscriptBuilder, TranscriptDescriptor};

type SparkCommitment<F, CS> = CommittedStructure<F, SparkEvalCheck<2>, CS>;

/// key to create and verify proofs for a given circuit
pub struct CircuitKey<
    F: Field,
    D: Duplex<F>,
    C,
    CS: CommmitmentScheme<F>,
    const IO: usize = 0,
    const S: usize = 0,
> {
    _circuit: PhantomData<C>,
    pub transcript: TranscriptDescriptor<F, D>,
    pub ccs_structure: CcsStructure<IO, S, F>,
    pub spark_structure: [SparkMatrix<F>; IO],
    pub spark_commitments: [SparkCommitment<F, CS>; IO],
    pub committment_scheme: CS,
}

impl<F, T, C, CS, const IO: usize, const S: usize> CircuitKey<F, T, C, CS, IO, S>
where
    F: Field,
    T: Duplex<F>,
    CS: CommmitmentScheme<F>,
{
    pub fn new<const IN: usize, const OUT: usize, const PRIV_OUT: usize>() -> Self
    where
        C: Circuit<F, IN, OUT, PRIV_OUT>,
    {
        let ccs_structure = C::structure();
        let vars = ccs_structure.vars();
        let spark_structure = ccs_structure.io_matrices.clone().map(|matrix: Matrix| {
            let evals = matrix
                .to_evals()
                .into_iter()
                .map(|index| {
                    let (i, j) = index;
                    ([i, j], F::one())
                })
                .collect();
            SparkMatrix::<F>::new(evals)
        });
        let committment_scheme = CS::new(8);
        let dummy_point = vec![F::zero(); vars];
        let dummy_point = MultiPoint::new(dummy_point);
        let dummy_points = [dummy_point.clone(), dummy_point.clone()];
        let spark_commitments = spark_structure.each_ref().map(|s| {
            let points = dummy_points.clone();
            let challenges = SparkChallenges::default();
            let zero_check_point = dummy_point.clone();
            let mles = SparkEval::<F, 2>::evals(s, points, challenges, zero_check_point);
            let commitment: SparkCommitment<F, CS> =
                CommittedStructure::commit(&committment_scheme, mles);
            commitment
        });
        let transcript_builder = TranscriptBuilder::new(vars);
        //TODO: make transcript
        let transcript = transcript_builder.finish();

        Self {
            _circuit: PhantomData,
            transcript,
            ccs_structure,
            spark_structure,
            spark_commitments,
            committment_scheme,
        }
    }
}
