use crate::{
    batching::{reduction::BatchReduction, BatchEval, BatchingError},
    CommmitmentScheme2, OpenInstance,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::{
    protocols::Reduction, Message, MessageGuard, Transcript, TranscriptBuilder, TranscriptGuard,
};

/// To batch many open instances and redeuce them into a single one, additionally
/// acepts an structure of commitments to be batched together.
pub struct StructuredBatchReduction<F: Field, S: CommmitmentScheme2<F>> {
    _phantom: PhantomData<(F, S)>,
    structure: Vec<S::Commitment>,
    structure_mles: Vec<Vec<F>>,
}

/// Extension [BatchEval] including evaluations of public commitments.
pub struct StructuredBatchEval<F: Field, S: CommmitmentScheme2<F>> {
    dynamic_batch: BatchEval<F, S>,
    /// Only the evaluations are here as the commitments are part
    /// of the structure.
    structure_evals: Vec<F>,
}

/// Number of commitments in the strucuture
pub struct StructureLength;

impl<F: Field, S: CommmitmentScheme2<F>> Message<F> for StructuredBatchEval<F, S> {
    fn len(vars: usize, param_resolver: &transcript::params::ParamResolver) -> usize {
        let structure_length = param_resolver.get::<StructureLength>();
        BatchEval::<F, S>::len(vars, param_resolver) + structure_length
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = self.dynamic_batch.to_field_elements();
        elems.extend(self.structure_evals.clone());
        elems
    }
}

impl<F, S> Reduction<F> for StructuredBatchReduction<F, S>
where
    F: Field,
    S: CommmitmentScheme2<F> + 'static,
{
    type A = StructuredBatchEval<F, S>;

    type B = OpenInstance<F, S::Commitment>;

    type Key = Self;

    type Proof = ();

    type Error = BatchingError<S::Error>;

    fn transcript_pattern(builder: TranscriptBuilder<F>) -> TranscriptBuilder<F> {
        builder.round::<BatchEval<F, S>, 1>()
    }

    fn verify_reduction<D: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        transcript: &mut TranscriptGuard<F, D, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [chall]) = transcript
            .unwrap_guard(instance)
            .map_err(BatchingError::Transcript)?;
        let StructuredBatchEval {
            dynamic_batch:
                BatchEval {
                    point,
                    commitments_and_evals,
                },
            structure_evals,
        } = instance;
        // shouldn't fail as the transcript will catch this issue first.
        assert_eq!(structure_evals.len(), key.structure.len());

        let structure_commits: Vec<S::Commitment> = key.structure.clone();
        let structure = structure_commits.into_iter().zip(structure_evals);

        let mut iter = commitments_and_evals.into_iter();
        let first: (S::Commitment, F) = iter.next().unwrap();

        let (commit, eval) = iter.into_iter().chain(structure).fold(first, |acc, e| {
            let (commit, eval) = acc;
            let commit = commit * chall + &e.0;
            let eval = eval * chall + eval;
            (commit, eval)
        });

        Ok(OpenInstance {
            commit,
            point,
            eval,
        })
    }
}

impl<F: Field, S: CommmitmentScheme2<F> + 'static> StructuredBatchReduction<F, S> {
    pub fn batch_mles<D: Duplex<F>>(
        &self,
        instance: BatchEval<F, S>,
        mles: &[&[F]],
        transcript: &mut Transcript<F, D>,
    ) -> Result<Vec<F>, transcript::Error> {
        let [chall] = transcript.send_message(&instance)?;
        Ok(self.combine(mles, chall))
    }
    fn combine(&self, mles: &[&[F]], chall: F) -> Vec<F> {
        let length = mles[0].len();
        for i in 0..mles.len() {
            assert_eq!(length, mles[i].len());
        }
        let mut combined: Vec<F> = BatchReduction::<F, S>::combine(mles, chall);
        for i in 0..self.structure.len() {
            let mle: &[F] = &self.structure_mles[i];
            combined.iter_mut().zip(mle).for_each(|(combined, mle)| {
                *combined *= chall;
                *combined += mle;
            });
        }
        combined
    }
}
