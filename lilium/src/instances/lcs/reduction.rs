use crate::{
    circuit_key::KeySparkStructure,
    instances::{
        lcs::{
            key::LcsKey,
            sumcheck_argument::{LcsMles, LcsSumcheck, SingleChall},
            LcsInstance, LcsProver,
        },
        linearized::LinearizedInstance,
    },
};
use ark_ff::Field;
use commit::{
    batching::{structured::StructuredBatchEval, BatchEval},
    committed_structure::CommittedStructure,
    CommmitmentScheme, OpenInstance,
};
use sponge::sponge::Duplex;
use std::usize;
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
    selector_evals: Vec<F>,
    witness_eval: F,
    matrix_evals: [F; IO],
}

impl<F, C, const I: usize, const IO: usize> Reduction<F> for LcsProver<C, I, IO>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type Key = LcsKey<F, C, IO>;

    type A = LcsInstance<F, C, I>;

    type B = (
        LinearizedInstance<F, C, I, IO>,
        OpenInstance<F, C::Commitment>,
    );

    type Proof = LcsReductionProof<F, IO>;

    type Error = crate::Error<F, C>;

    fn transcript_pattern(builder: TranscriptBuilder<F>) -> TranscriptBuilder<F> {
        builder
            .round::<Self::A, 1>()
            .point()
            .add_reduction_patter::<SumcheckVerifier<F, LcsSumcheck<F, IO, 4>>>()
            .add_reduction_patter::<CommittedStructure<F, LcsSumcheck<F, IO, 4>, C>>()
            .round::<[SingleElement<F>; IO], 0>()
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
        //TODO: add selectors
        //TODO: create once and store in key.
        let sumcheck_verifier = SumcheckVerifier::<F, LcsSumcheck<F, IO, 4>>::new(vars);
        // As the expected sum is zero.
        let sumcheck_instance = MessageGuard::new(Sum(F::zero()));

        // Receive sumcheck proof.
        let proof = transcript.receive_message_delayed(|p| p.sumcheck.clone());
        // Verifying sumcheck proof, reducing instance to point eval check.
        let check: PolyEvalCheck<F> = SumcheckVerifier::verify_reduction(
            &sumcheck_verifier,
            sumcheck_instance,
            transcript.new_guard(proof),
        )?;

        // Point where to evaluate the sumcheck polynomial.
        let check_point = MultiPoint::new(check.vars.clone());

        // Create instance for evaluation of committed MLEs.
        let instance = transcript.receive_message_delayed(|proof| {
            let point = check_point.clone();
            let commitments_and_evals = vec![(witness_commit.clone(), proof.witness_eval.clone())];
            let dynamic_batch = BatchEval::new(point, commitments_and_evals);
            let structure_evals = proof.selector_evals.clone();
            StructuredBatchEval::new(dynamic_batch, structure_evals)
        });

        // Verify commitment's openings in the point. Reducing to a single
        // opening instance.
        let instance: MessageGuard<StructuredBatchEval<F, C>> = instance;
        let tr = transcript.new_guard(());
        let key = &key.committed_structure;
        // The reduction also outputs the claimed evals.
        let (open, committed_evals) = CommittedStructure::verify_reduction(&key, instance, tr)?;

        // Assembling different types of evals into a single one.
        let evals: LcsMles<F, IO, 4> = {
            let small_evals: LcsMles<Option<F>, IO, 4> = LcsMles::<Option<F>, IO, 4>::small_evals(
                check_point.clone(),
                r_eq,
                public_inputs.to_vec(),
            );

            let evals = committed_evals.combine(&small_evals, Option::xor);

            // Matrix evals are just received from the prover, a linearized instace
            // is create to verify them later.
            let (matrix_evals, []) = transcript.receive_message(|proof| {
                let matrix_evals = proof.matrix_evals;
                matrix_evals.map(SingleElement)
            })?;

            let matrix_evals: [F; IO] = matrix_evals.map(SingleElement::inner);

            let products = LcsMles::new_only_products(matrix_evals);
            let evals = products.combine(&evals, Option::xor);
            let evals = LcsSumcheck::<F, IO, 4>::map_evals(evals, Option::unwrap);
            evals
        };

        // Instance to be verified for the matrix evals.
        let linearized_instance: LinearizedInstance<F, C, I, IO> = {
            let products: [F; IO] = *evals.products();
            let u = F::one();
            let rx = check_point;
            let l = LinearizedInstance {
                witness_commit,
                u,
                public_inputs,
                rx,
                products,
            };
            l
        };

        let evals: LcsMles<F, IO, 4> = evals;
        let challs = SingleChall::from(sumcheck_chall);

        // Check evaluation on the point.
        let checks = sumcheck_verifier.check_evals_at_r(evals, check.eval, &challs);
        if checks {
            return Err(crate::Error::EvalCheck);
        }

        Ok((linearized_instance, open))
    }
}
