use crate::{
    folding::{SumFold, SumFoldInstance, SumFoldProof},
    message::Message,
    sumcheck::{Sum, SumcheckFunction},
};
use ark_ff::Field;
use transcript::{protocols::Reduction, MessageGuard, TranscriptBuilder, TranscriptGuard};

impl<F: Field, SF: SumcheckFunction<F>> Reduction<F> for SumFold<F, SF> {
    type A = SumFoldInstance<F, 2>;

    type B = Sum<F>;

    type Key = Self;

    type Proof = SumFoldProof<F>;

    type Error = ();

    fn transcript_pattern(_key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder
            .round::<F, SumFoldInstance<F, 2>, 1>()
            //TODO: check length
            .round::<F, Message<F>, 1>()
    }

    fn verify_reduction<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [beta]) = transcript.unwrap_guard(instance).unwrap();
        // eq(x,beta) = x * beta + (1-x) * (1-beta)
        // eq(0,beta) = 1 - beta
        // eq(1,beta) = beta
        let sum = beta * instance.sums[0].0 + (F::one() - beta) * instance.sums[1].0;

        let (msg, [r]) = transcript
            .receive_message(|proof| proof.message.clone())
            .unwrap();

        //TODO: error
        assert_eq!(sum, msg.eval_at_0() + msg.eval_at_1());

        let eqr = r * beta + (F::one() - r) * (F::one() - beta);

        // This would be the sum of eq(beta,r) * f(r,...)
        let new_sum = msg.eval_at_x(r, &key.extended_weights);
        // Thus, removing eq(beta,r) leaves just the sum of f(r,...)
        let new_sum = Sum(new_sum / eqr);
        Ok(new_sum)
    }
}
