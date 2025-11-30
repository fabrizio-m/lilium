use crate::{
    challenges::SparkChallenges, evals::SparkEval, spark::SparkEvalCheck, structure::SparkStructure,
};
use ark_ff::Field;
use commit::{
    batching::{structured::StructuredBatchEval, BatchingError},
    committed_structure::CommittedStructure,
    CommmitmentScheme, OpenInstance,
};
use sponge::sponge::Duplex;
use std::rc::Rc;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::{Sum, SumcheckFunction, SumcheckVerifier},
    SumcheckError,
};
use transcript::{
    params::ParamResolver, protocols::Reduction, Message, MessageGuard, TranscriptGuard,
};

mod prove;

pub use prove::ProverOutput;

//TODO: add prover for the reduction

#[derive(Clone, Debug)]
pub struct CommittedSpark<F: Field, C: CommmitmentScheme<F>, const D: usize> {
    // structure: SparkStructure<F, D>,
    committed_structure: CommittedStructure<F, SparkEvalCheck<D>, C>,
    structure: Rc<SparkStructure<F, D>>,
    sumcheck_verifier: SumcheckVerifier<F, SparkEvalCheck<D>>,
}

pub struct CommittedSparkInstance<F: Field, const D: usize> {
    point: [MultiPoint<F>; D],
    eval: F,
}

impl<F: Field, const D: usize> CommittedSparkInstance<F, D> {
    pub fn new(point: [MultiPoint<F>; D], eval: F) -> Self {
        Self { point, eval }
    }
}

impl<F: Field, const D: usize> Message<F> for CommittedSparkInstance<F, D> {
    fn len(vars: usize, _param_resolver: &ParamResolver) -> usize {
        vars * D + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = Vec::with_capacity(self.point[0].vars() * D + 1);
        elems.extend(self.point.iter().cloned().flat_map(MultiPoint::inner));
        elems.push(self.eval);
        elems
    }
}

#[derive(Debug, Clone)]
pub struct CommittedSparkProof<F: Field, C: CommmitmentScheme<F>, const D: usize> {
    sumcheck_proof: sumcheck::sumcheck::Proof<F, SparkEvalCheck<D>>,
    committed_evals: StructuredBatchEval<F, C>,
}

#[derive(Debug, Clone)]
pub enum Error<F: Field, C: CommmitmentScheme<F>> {
    Transcript(transcript::Error),
    Sumcheck(SumcheckError),
    Batching(BatchingError<F, C>),
    /// Final eval check at r failed
    EvalCheck,
}

impl<F: Field, C: CommmitmentScheme<F>> From<transcript::Error> for Error<F, C> {
    fn from(value: transcript::Error) -> Self {
        Self::Transcript(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<SumcheckError> for Error<F, C> {
    fn from(value: SumcheckError) -> Self {
        Self::Sumcheck(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<BatchingError<F, C>> for Error<F, C> {
    fn from(value: BatchingError<F, C>) -> Self {
        Self::Batching(value)
    }
}

impl<F, C, const D: usize> Reduction<F> for CommittedSpark<F, C, D>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = CommittedSparkInstance<F, D>;

    type B = OpenInstance<F, C::Commitment>;

    type Key = Self;

    type Proof = CommittedSparkProof<F, C, D>;

    type Error = Error<F, C>;

    fn transcript_pattern(
        builder: transcript::TranscriptBuilder<F>,
    ) -> transcript::TranscriptBuilder<F> {
        builder
            .round::<CommittedSparkInstance<F, D>, 3>()
            .point()
            .add_reduction_patter::<SumcheckVerifier<F, SparkEvalCheck<D>>>()
            .add_reduction_patter::<CommittedStructure<F, SparkEvalCheck<D>, C>>()
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let vars = key.committed_structure.vars();
        let (instance, challs) = transcript.unwrap_guard(instance)?;
        let [c1, c2, c3] = challs;

        let challenges = SparkChallenges::new(c1, c2, c3);
        let zero_check_point = MultiPoint::new(transcript.point()?);

        let CommittedSparkInstance { point, eval } = instance;
        // shouldn't fail
        assert_eq!(point[0].vars(), vars);
        let sumcheck_instance = MessageGuard::new(Sum(eval));

        let sumcheck_proof =
            transcript.receive_message_delayed(|proof| proof.sumcheck_proof.clone());

        let reduced = SumcheckVerifier::verify_reduction(
            &key.sumcheck_verifier,
            sumcheck_instance,
            transcript.new_guard(sumcheck_proof),
        )?;

        let r = MultiPoint::new(reduced.vars);
        let zero_eq_eval = zero_check_point.eval_as_eq(&r);
        let eq_evals = point.map(|x| x.eval_as_eq(&r));
        let small_evals = SparkEval::<F, D>::small_evals(zero_eq_eval, eq_evals);
        let instance = transcript.receive_message_delayed(|proof| proof.committed_evals.clone());
        let (open_instance, evals) = CommittedStructure::verify_reduction(
            &key.committed_structure,
            instance,
            transcript.new_guard(()),
        )?;

        let evals = evals.combine(&small_evals, |committed, small| committed.xor(small));
        // shouldn't fail as lengths should be checked at this point
        let evals: SparkEval<F, D> =
            <SparkEvalCheck<D> as SumcheckFunction<F>>::map_evals(evals, Option::unwrap);

        let checks = key
            .sumcheck_verifier
            .check_evals_at_r(evals, reduced.eval, &challenges);
        if checks {
            Ok(open_instance)
        } else {
            Err(Error::EvalCheck)
        }
    }
}

impl<F: Field, C: CommmitmentScheme<F>, const D: usize> CommittedSpark<F, C, D> {
    pub fn new(structure: Rc<SparkStructure<F, D>>, scheme: &C) -> Self {
        assert!(structure.val.len().is_power_of_two());
        let vars = structure.val.len().ilog2() as usize;

        let dummy_point = MultiPoint::new(vec![F::zero(); vars]);
        let points = [(); D].map(|_| dummy_point.clone());
        let challenges = SparkChallenges::default();
        let zero_check_point = dummy_point;

        let mles = SparkEval::<F, D>::evals(&structure, points, challenges, zero_check_point);

        let committed_structure = CommittedStructure::new(Rc::new(mles), scheme);
        let sumcheck_verifier: SumcheckVerifier<F, SparkEvalCheck<D>> = SumcheckVerifier::new(vars);

        Self {
            committed_structure,
            structure,
            sumcheck_verifier,
        }
    }
}
