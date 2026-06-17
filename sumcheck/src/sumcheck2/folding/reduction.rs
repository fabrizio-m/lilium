use crate::{
    barycentric_eval::BarycentricWeights,
    folding::utils::FieldFolder,
    sumcheck2::{
        evals::Mles, oracles::Oracle, SumcheckInstance, SumcheckMessage, SumcheckRelation,
    },
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::reduction2::{
    FoldingRelation, GuardedProof, ProverOutput, Reduction, Transcript, TranscriptBuilder,
    VerifierTranscript,
};

pub struct SumFold<F, O>(PhantomData<(F, O)>);

pub struct SumFoldKey<F: Field> {
    // Weights for degree d.
    // weights: BarycentricWeights<F>,
    // Weights for degree d + 1.
    extended_weights: BarycentricWeights<F>,
    degree: usize,
}

trait Foldable<F> {
    fn fold(folder: &FieldFolder<F>, a: Self, b: Self) -> Self;
}

impl<F, O> Reduction<F, FoldingRelation<SumcheckRelation<F, O>>, SumcheckRelation<F, O>>
    for SumFold<F, O>
where
    F: Field,
    O: Oracle<F>,
    O::Instance: Foldable<F>,
{
    type ProverKey = SumFoldKey<F>;

    type VerifierKey = SumFoldKey<F>;

    type Proof = SumcheckMessage<F>;

    type Error = ();

    fn transcript_pattern(
        key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        let degree = key.degree + 1;
        builder.round::<F, SumcheckMessage<F>, 1>(&degree)
    }

    fn verifier_key(_structure_1: &O, _structure_2: &O) -> Self::VerifierKey {
        todo!()
    }

    fn key_pair(_structure_1: &O, _structure_2: &O) -> (Self::VerifierKey, Self::ProverKey) {
        todo!()
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: [SumcheckInstance<F, O>; 2],
        _witness: [Vec<Mles<O::Function, F>>; 2],
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<SumcheckRelation<F, O>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: [SumcheckInstance<F, O>; 2],
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<SumcheckInstance<F, O>, Self::Error> {
        // TODO: handle
        let (_, [beta]) = transcript
            .receive_message(|_| (), &GuardedProof::empty(), &())
            .unwrap();
        // eq(x,beta) = x * beta + (1-x) * (1-beta)
        // eq(0,beta) = 1 - beta
        // eq(1,beta) = beta
        let sum = (F::one() - beta) * instance[0].sum + beta * instance[1].sum;

        // A single sumcheck round, we get message from prover, generate challenge
        // r, check message agrees with original sum.
        // And then the work is reduced to a new sumcheck instance over the same polynomial
        // with 1 variable fixed with r.
        // TODO: handle
        let (msg, [r]) = transcript
            .receive_message(Clone::clone, &proof, &(key.degree + 1))
            .unwrap();
        let msg = msg.to_message();

        if sum != msg.eval_at_0() + msg.eval_at_1() {
            // return Err(SumcheckError::RoundSum);
            // TODO: handle
            panic!()
        }

        let eqr = r * beta + (F::one() - r) * (F::one() - beta);

        // This would be the sum of eq(beta,r) * f(r,...)
        let new_sum = msg.eval_at_x(r, &key.extended_weights);
        // Thus, removing eq(beta,r) leaves just the sum of f(r,...)
        let sum = new_sum / eqr;
        let oracle_instance = {
            let folder = FieldFolder::new(r);
            let [a, b] = instance;
            Foldable::fold(&folder, a.oracle_instance, b.oracle_instance)
        };
        Ok(SumcheckInstance {
            sum,
            oracle_instance,
        })
    }
}
