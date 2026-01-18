use crate::instances::{
    lcs::{
        key::LcsReductionKey,
        sumcheck_argument::{LcsMles, LcsSumcheck, SingleChall},
        LcsInstance,
    },
    linearized::LinearizedInstance,
};
use ark_ff::Field;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::{Sum, SumcheckFunction, SumcheckVerifier},
};
use transcript::{
    instances::PolyEvalCheck, messages::SingleElement, protocols::Reduction, MessageGuard,
    TranscriptBuilder, TranscriptGuard,
};

/// Proof for the LCS -> Linearized reduction.
#[derive(Debug, Clone)]
pub struct LcsReductionProof<F: Field, const IO: usize> {
    sumcheck: sumcheck::sumcheck::Proof<F, LcsSumcheck<F, IO, 4>>,
    selector_evals: [F; 4],
    witness_eval: F,
    products: [F; IO],
}

impl<F: Field, const IO: usize> LcsReductionProof<F, IO> {
    pub(crate) fn new(
        sumcheck: sumcheck::sumcheck::Proof<F, LcsSumcheck<F, IO, 4>>,
        selector_evals: [F; 4],
        witness_eval: F,
        products: [F; IO],
    ) -> Self {
        Self {
            sumcheck,
            selector_evals,
            witness_eval,
            products,
        }
    }
}

pub struct LcsReduction<C, const I: usize, const IO: usize>(PhantomData<C>);

impl<F, C, const I: usize, const IO: usize> Reduction<F> for LcsReduction<C, I, IO>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type Key = LcsReductionKey<F, C, IO>;

    type A = LcsInstance<F, C, I>;

    type B = LinearizedInstance<F, C, IO, 4>;

    type Proof = LcsReductionProof<F, IO>;

    type Error = crate::Error<F, C>;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        let sumcheck_verifier = &key.sumcheck_verifier;
        builder
            .round::<F, Self::A, 1>()
            .point()
            .add_reduction_patter::<F, SumcheckVerifier<F, LcsSumcheck<F, IO, 4>>>(
                sumcheck_verifier,
            )
            .round::<F, [SingleElement<F>; 4], 0>()
            .round::<F, SingleElement<F>, 0>()
            .round::<F, [SingleElement<F>; IO], 0>()
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let vars = key.domain_vars;

        // Unwrap isntance, get challenge for sumcheck.
        let (lcs_instance, [sumcheck_chall]) = transcript.unwrap_guard(instance)?;
        let LcsInstance {
            witness_commit,
            public_inputs,
        } = lcs_instance;

        // Get challenge point for sumcheck's zero-check.
        let r_eq = transcript.point()?;
        let r_eq = MultiPoint::new(r_eq);
        let sumcheck_verifier = &key.sumcheck_verifier;
        // As the expected sum is zero.
        let sumcheck_instance = MessageGuard::new(Sum(F::zero()));

        // Receive sumcheck proof.
        let proof = transcript.receive_message_delayed(|p| p.sumcheck.clone());
        // Verifying sumcheck proof, reducing instance to point eval check.
        let check: PolyEvalCheck<F> = SumcheckVerifier::verify_reduction(
            sumcheck_verifier,
            sumcheck_instance,
            transcript.new_guard(proof),
        )?;

        // Point where to evaluate the sumcheck polynomial.
        let check_point = MultiPoint::new(check.vars.clone());

        // Assembling different types of evals into a single one.
        let evals: LcsMles<F, IO, 4> = {
            let small_evals: LcsMles<Option<F>, IO, 4> = LcsMles::<Option<F>, IO, 4>::small_evals(
                check_point.clone(),
                r_eq,
                public_inputs.to_vec(),
            );

            // Committed evals provided by prover and verification deferred
            // to the linearized instance.
            let (selector_evals, []) =
                transcript.receive_message(|proof| proof.selector_evals.map(SingleElement))?;
            let (w_eval, []) =
                transcript.receive_message(|proof| SingleElement(proof.witness_eval))?;
            let committed_evals =
                LcsMles::from_committed_evals(w_eval.0, selector_evals.map(SingleElement::inner));

            let evals = committed_evals.combine(&small_evals, Option::xor);

            // Matrix evals are just received from the prover, a linearized instance
            // is create to verify them later.
            let (products, []) = transcript.receive_message(|proof| {
                let products = proof.products;
                products.map(SingleElement)
            })?;

            let products: [F; IO] = products.map(SingleElement::inner);

            let products = LcsMles::new_only_products(products);
            let evals = products.combine(&evals, Option::xor);
            LcsSumcheck::<F, IO, 4>::map_evals(evals, Option::unwrap)
        };

        // Instance to be verified for the matrix evals.
        let linearized_instance: LinearizedInstance<F, C, IO, 4> = {
            let products: [F; IO] = *evals.products();
            let rx = check_point;
            let selector_evals = *evals.gate_selectors();
            let witness_eval = *evals.w();
            LinearizedInstance {
                witness_commit,
                witness_eval,
                rx,
                products,
                selector_evals,
            }
        };

        let evals: LcsMles<F, IO, 4> = evals;
        let challs = SingleChall::from(sumcheck_chall);

        // Check evaluation on the point.
        let checks = sumcheck_verifier.check_evals_at_r(evals, check.eval, &challs);
        if checks {
            return Err(crate::Error::EvalCheck);
        }

        Ok(linearized_instance)
    }
}
