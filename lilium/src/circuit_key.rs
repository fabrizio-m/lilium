use ark_ff::Field;
use ccs::{
    circuit::{BuildStructure, Circuit},
    structure::{CcsStructure, Matrix},
};
use commit::CommmitmentScheme;
use spark::{committed_spark::CommittedSpark, structure::SparkMatrix};
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use sumcheck::sumcheck::DegreeParam;
use transcript::{params::ParamResolver, TranscriptBuilder, TranscriptDescriptor};

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
    pub ccs_structure: CcsStructure<IO, S>,
    pub spark_structure: [SparkMatrix<F>; IO],
    pub spark_commitments: [CommittedSpark<F, CS, 2>; IO],
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
        let spark_commitments = spark_structure.each_ref().map(|s| {
            let commitment = CommittedSpark::new(s, &committment_scheme);
            commitment
        });

        // This assumes IO is selected properly, which should be fine as it
        // can be higher than needed but not lower.
        let degree = IO;
        /// TODO: more params needed
        let mut resolver = ParamResolver::new();
        resolver.set::<DegreeParam>(degree);
        let transcript_builder = TranscriptBuilder::new(vars, resolver);
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

// key abstractions

pub trait AbstractKey<F: Field> {
    fn domain_vars(&self) -> usize;
}

pub trait KeyCommitment<F, C>: AbstractKey<F>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn pcs(&self) -> &C;
}
pub trait KeySparkStructure<F, C, const IO: usize>: KeyCommitment<F, C>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn spark_structure(&self) -> &[SparkMatrix<F>; IO];
    fn spark_keys(&self) -> &[CommittedSpark<F, C, 2>; IO];
}

impl<F: Field, D: Duplex<F>, C, CS: CommmitmentScheme<F>, const IO: usize, const S: usize>
    AbstractKey<F> for CircuitKey<F, D, C, CS, IO, S>
{
    fn domain_vars(&self) -> usize {
        self.ccs_structure.vars()
    }
}

impl<F: Field, D: Duplex<F>, C, CS: CommmitmentScheme<F>, const IO: usize, const S: usize>
    KeyCommitment<F, CS> for CircuitKey<F, D, C, CS, IO, S>
{
    fn pcs(&self) -> &CS {
        &self.committment_scheme
    }
}

impl<F: Field, D: Duplex<F>, C, CS: CommmitmentScheme<F>, const IO: usize, const S: usize>
    KeySparkStructure<F, CS, IO> for CircuitKey<F, D, C, CS, IO, S>
{
    fn spark_structure(&self) -> &[SparkMatrix<F>; IO] {
        &self.spark_structure
    }

    fn spark_keys(&self) -> &[CommittedSpark<F, CS, 2>; IO] {
        &self.spark_commitments
    }
}
