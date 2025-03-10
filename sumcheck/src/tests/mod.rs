use crate::{
    polynomials::{EvalsExt, MultiPoint},
    sumcheck::{DegreeParam, Sum, SumcheckFunction, SumcheckProver, SumcheckVerifier},
};
use ark_ff::Field;
use sponge::{permutation::UnsafePermutation, sponge::Sponge};
use transcript::{
    instances::PolyEvalCheck, params::ParamResolver, protocols::Reduction, MessageGuard,
    Transcript, TranscriptBuilder, TranscriptDescriptor, TranscriptGuard,
};

#[cfg(test)]
mod mul_square;
#[cfg(test)]
mod sum_of_products;
#[cfg(test)]
mod zero_check;

pub type TestSponge<F> = Sponge<F, UnsafePermutation<F, 3>, 2, 1, 3>;

pub fn sumcheck_transcript<F, SF>(vars: usize) -> TranscriptDescriptor<F, TestSponge<F>>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    let degree = crate::sumcheck::sumcheck_degree::<F, SF>();
    let mut resolver = ParamResolver::new();
    resolver.set::<DegreeParam>(degree);
    let transcript_builder = TranscriptBuilder::new(vars, resolver);
    let transcript_descriptor =
        SumcheckVerifier::<F, SF>::transcript_pattern(transcript_builder).finish();
    transcript_descriptor
}

/// Creates a prove with the mle and tries to verify it.
pub fn prove_and_verify<F, SF>(mle: Vec<SF::Mles<F>>, sum: F, challs: SF::Challs)
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    let vars = mle.len().ilog2() as usize;

    let transcript_desc = sumcheck_transcript::<F, SF>(vars);

    let prover = SumcheckProver::<F, SF>::new(vars);
    let mut transcript: Transcript<F, TestSponge<F>> = transcript_desc.instanciate();
    let proof = prover.prove(&mut transcript, mle.clone(), &challs).unwrap();
    transcript.finish().unwrap();

    let instance = MessageGuard::new(Sum(sum));
    let verifier = SumcheckVerifier::<F, SF>::new(vars);
    let mut transcript = transcript_desc.instanciate();
    let check = {
        let transcript = TranscriptGuard::new(&mut transcript, proof);

        let check = SumcheckVerifier::verify_reduction(&verifier, instance, transcript).unwrap();
        check
    };
    transcript.finish().unwrap();

    let PolyEvalCheck { vars, eval } = check;
    let r = MultiPoint::new(vars);

    let evals = EvalsExt::eval(&mle, r);
    assert!(verifier.check_evals_at_r(evals, eval, &challs));
}
