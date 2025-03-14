use crate::{challenges::SparkChallenges, evals::SparkEval, spark::SparkEvalCheck};
use ark_ff::Field;
use commit::{
    batching::{structured::StructuredBatchEval, BatchingError},
    committed_structure2::CommittedStructure,
    CommmitmentScheme2, OpenInstance,
};
use sponge::sponge::Duplex;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::{Sum, SumcheckFunction, SumcheckVerifier},
    SumcheckError,
};
use transcript::{
    params::ParamResolver, protocols::Reduction, Message, MessageGuard, TranscriptGuard,
};

struct CommittedSpark<F: Field, C: CommmitmentScheme2<F>, const D: usize> {
    // structure: SparkStructure<F, D>,
    committed_structure: CommittedStructure<F, SparkEvalCheck<D>, C>,
    sumcheck_verifier: SumcheckVerifier<F, SparkEvalCheck<D>>,
}

struct CommittedSparkInstance<F: Field, const D: usize> {
    point: [MultiPoint<F>; D],
    eval: F,
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

struct CommittedSparkProof<F: Field, C: CommmitmentScheme2<F>, const D: usize> {
    sumcheck_proof: sumcheck::sumcheck::Proof<F, SparkEvalCheck<D>>,
    committed_evals: StructuredBatchEval<F, C>,
}

pub enum Error<E> {
    Transcript(transcript::Error),
    Sumcheck(SumcheckError),
    Batching(BatchingError<E>),
    /// Final eval check at r failed
    EvalCheck,
}

impl<E> From<transcript::Error> for Error<E> {
    fn from(value: transcript::Error) -> Self {
        Self::Transcript(value)
    }
}

impl<E> From<SumcheckError> for Error<E> {
    fn from(value: SumcheckError) -> Self {
        Self::Sumcheck(value)
    }
}

impl<E> From<BatchingError<E>> for Error<E> {
    fn from(value: BatchingError<E>) -> Self {
        Self::Batching(value)
    }
}

impl<F, C, const D: usize> Reduction<F> for CommittedSpark<F, C, D>
where
    F: Field,
    C: CommmitmentScheme2<F> + 'static,
{
    type A = CommittedSparkInstance<F, D>;

    type B = OpenInstance<F, C::Commitment>;

    type Key = Self;

    type Proof = CommittedSparkProof<F, C, D>;

    type Error = Error<C::Error>;

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
            transcript.new_guard(().into()),
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
