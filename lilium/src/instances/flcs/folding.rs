use crate::flcs::{sumcheck_reduction::LcsSumfold, FoldableLcsInstance};
use ark_ff::Field;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use sumcheck::folding::SumFold;
use transcript::{protocols::Reduction, MessageGuard, TranscriptBuilder, TranscriptGuard};

struct LcsFolding<F, C, const IO: usize> {
    _phantom: PhantomData<(F, C)>,
}

struct LcsFoldingKey<F: Field, const IO: usize> {
    vars: usize,
    sumfold: SumFold<F, LcsSumfold<F, IO, 4>>,
}

impl<F, C, const IO: usize> Reduction<F> for LcsFolding<F, C, IO>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = [FoldableLcsInstance<F, C, IO>; 2];

    type B = FoldableLcsInstance<F, C, IO>;

    type Key = LcsFoldingKey<F, IO>;

    type Proof = ();

    type Error = ();

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        todo!()
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instances, []): ([FoldableLcsInstance<F, C, IO>; 2], _) =
            transcript.unwrap_guard(instance).unwrap();

        // let sumfold = SumFold::new(f)
        let r = SumFold::verify_reduction(&key.sumfold, instance, transcript);
        todo!()
    }
}
