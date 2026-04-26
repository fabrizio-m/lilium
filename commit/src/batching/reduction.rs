use crate::{
    batching::{BatchEval, BatchingError},
    CommmitmentScheme, OpenInstance,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::{protocols::Reduction, MessageGuard, TranscriptBuilder, TranscriptGuard};

/// to batch many open instances and redeuce them into a single one
pub struct BatchReduction<F: Field, S: CommmitmentScheme<F>> {
    _phantom: PhantomData<(F, S)>,
}

impl<F: Field, S> Reduction<F> for BatchReduction<F, S>
where
    F: Field,
    S: CommmitmentScheme<F> + 'static,
{
    type A = BatchEval<F, S>;

    type B = OpenInstance<F, S::Commitment>;

    type Key = Self;

    type Proof = ();

    type Error = BatchingError<F, S>;

    fn transcript_pattern(_key: &Self, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder.round::<F, BatchEval<F, S>, 1>()
    }

    fn verify_reduction<D: Duplex<F>>(
        _key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, D, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [chall]) = transcript.unwrap_guard(instance)?;

        let BatchEval {
            point,
            commitments_and_evals,
        } = instance;

        let mut iter = commitments_and_evals.into_iter();
        let first = iter.next().unwrap();

        let (commit, eval) = iter.fold(first, |acc, e| {
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

/*impl<F: Field, S: CommmitmentScheme2<F> + 'static> BatchReduction<F, S> {
    pub fn batch_mles<D: Duplex<F>>(
        instance: BatchEval<F, S>,
        mles: &[&[F]],
        transcript: &mut Transcript<F, D>,
    ) -> Result<Vec<F>, transcript::Error> {
        let [chall] = transcript.send_message(&instance)?;
        Ok(Self::combine(mles, chall))
    }

    pub(crate) fn combine(mles: &[&[F]], chall: F) -> Vec<F> {
        let length = mles[0].len();
        for i in 0..mles.len() {
            assert_eq!(length, mles[i].len());
        }
        let mut combined: Vec<F> = mles[0].to_vec();
        for i in 1..mles.len() {
            let mle: &[F] = mles[i];
            combined.iter_mut().zip(mle).for_each(|(combined, mle)| {
                *combined *= chall;
                *combined += mle;
            });
        }
        combined
    }
}*/
