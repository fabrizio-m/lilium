use crate::{
    folding::{SumFold, SumFoldInstance, SumFoldProof},
    message::Message,
    sumcheck::{DegreeParam, Sum, SumcheckFunction},
    SumcheckError,
};
use ark_ff::Field;
use transcript::{
    params::ParamResolver, protocols::Reduction, MessageGuard, TranscriptBuilder, TranscriptGuard,
};

impl<F: Field, SF: SumcheckFunction<F>> Reduction<F> for SumFold<F, SF> {
    type A = SumFoldInstance<F, 2>;

    type B = Sum<F>;

    type Key = Self;

    type Proof = SumFoldProof<F>;

    type Error = SumcheckError;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        let params = ParamResolver::new().set::<DegreeParam>(key.degree + 1);
        builder
            .round::<F, SumFoldInstance<F, 2>, 1>()
            .with_params(params, |builder| builder.round::<F, Message<F>, 1>())
    }

    fn verify_reduction<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [beta]) = transcript
            .unwrap_guard(instance)
            .map_err(SumcheckError::TranscriptError)?;
        // eq(x,beta) = x * beta + (1-x) * (1-beta)
        // eq(0,beta) = 1 - beta
        // eq(1,beta) = beta
        let sum = (F::one() - beta) * instance.sums[0].0 + beta * instance.sums[1].0;

        // A single sumcheck round, we get message from prover, generate challenge
        // r, check message agrees with original sum.
        // And then the work is reduced to a new sumcheck instance over the same polynomial
        // with 1 variable fixed with r.
        let (msg, [r]) = transcript
            .receive_message(|proof| proof.message.clone())
            .map_err(SumcheckError::TranscriptError)?;

        if sum != msg.eval_at_0() + msg.eval_at_1() {
            return Err(SumcheckError::RoundSum);
        }

        let eqr = r * beta + (F::one() - r) * (F::one() - beta);

        // This would be the sum of eq(beta,r) * f(r,...)
        let new_sum = msg.eval_at_x(r, &key.extended_weights);
        // Thus, removing eq(beta,r) leaves just the sum of f(r,...)
        let new_sum = Sum(new_sum / eqr);
        Ok(new_sum)
    }
}
