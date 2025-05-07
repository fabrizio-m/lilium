use crate::{
    circuit_key::KeySparkStructure,
    instances::{
        eval_input_selector, eval_ux,
        linearized::{
            sumcheck_argument::{LinearizedMles, LinearizedSumcheck, SingleChall},
            LinearizedInstance,
        },
        matrix_eval::BatchMatrixEvalInstance,
    },
};
use ark_ff::Field;
use commit::{CommmitmentScheme, OpenInstance};
use std::marker::PhantomData;
use sumcheck::{
    polynomials::MultiPoint,
    sumcheck::{Sum, SumcheckVerifier},
};
use transcript::{
    instances::PolyEvalCheck, messages::SingleElement, protocols::Reduction, MessageGuard,
};

//TODO: use `CommittedStructure`

/*
struct LinearizedInstanceProver<F, K, CS, const I: usize, const IO: usize>(PhantomData<(F, K, CS)>);

impl<F, K, CS, const I: usize, const IO: usize> Protocol<F>
    for LinearizedInstanceProver<F, K, CS, I, IO>
where
    F: Field,
    CS: CommmitmentScheme2<F> + 'static,
    K: KeySparkStructure<F, CS, IO>,
{
    type Key = K;

    type Instance = LinearizedInstance<F, CS, I, IO>;

    type Proof = ();

    type Error = ();

    fn transcript_pattern(
        builder: transcript::TranscriptBuilder<F>,
    ) -> transcript::TranscriptBuilder<F> {
        todo!()
    }

    fn prove(instance: Self::Instance) -> Self::Proof {
        todo!()
    }

    fn verify<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::Instance>,
        mut transcript: transcript::TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<(), Self::Error> {
        ///handle
        let (instance, []) = transcript.unwrap_guard(instance).unwrap();
        let LinearizedInstance {
            witness_commit,
            rx,
            u,
            public_inputs,
            matrix_evals,
        } = instance;
        todo!()
    }
}
*/
struct LinearizedInstanceReduction<F, K, CS, const I: usize, const IO: usize>(
    PhantomData<(F, K, CS)>,
);

pub struct LinearizedProof<F: Field, const IO: usize> {
    sumcheck_proof: sumcheck::sumcheck::Proof<F, LinearizedSumcheck<IO>>,
    w_eval: SingleElement<F>,
    matrix_evals: [SingleElement<F>; IO],
}

type Sumcheck<F, const IO: usize> = SumcheckVerifier<F, LinearizedSumcheck<IO>>;

impl<F, K, CS, const I: usize, const IO: usize> Reduction<F>
    for LinearizedInstanceReduction<F, K, CS, I, IO>
where
    F: Field,
    CS: CommmitmentScheme<F> + 'static,
    K: KeySparkStructure<F, CS, IO>,
{
    type A = LinearizedInstance<F, CS, I, IO>;

    type B = (
        BatchMatrixEvalInstance<F, IO>,
        OpenInstance<F, CS::Commitment>,
    );

    type Key = K;

    type Proof = LinearizedProof<F, IO>;

    type Error = crate::Error<F, CS>;

    fn transcript_pattern(
        builder: transcript::TranscriptBuilder<F>,
    ) -> transcript::TranscriptBuilder<F> {
        builder
            .round::<Self::A, 1>()
            .point()
            .add_reduction_patter::<Sumcheck<F, IO>>()
            .round::<SingleElement<F>, 0>()
            .round::<[SingleElement<F>; IO], 0>()
    }

    fn verify_reduction<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::A>,
        mut transcript: transcript::TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [chall]) = transcript.unwrap_guard(instance)?;
        let LinearizedInstance {
            witness_commit,
            u,
            public_inputs,
            rx,
            products,
        } = instance;

        let n_vars = key.domain_vars();

        // Starting from 0 as expected from the zero check for
        // the inputs.
        let sum = products.iter().fold(F::zero(), |acc, m| acc * chall + m);
        let sum = MessageGuard::new(Sum(sum));

        // Verifying sumcheck reduction to point evaluation check.
        let sumcheck_verifier = SumcheckVerifier::new(n_vars);
        let proof = transcript.receive_message_delayed(|proof| proof.sumcheck_proof.clone());
        // Point for zero check.
        let r_eq = MultiPoint::new(transcript.point()?);
        let reduced = Sumcheck::<F, IO>::verify_reduction(
            &sumcheck_verifier,
            sum,
            transcript.new_guard(proof),
        )?;
        let PolyEvalCheck { vars, eval } = reduced;

        // this eval will have to be verified with the commitment
        let (SingleElement(w_eval), []) = transcript.receive_message(|proof| proof.w_eval).unwrap();
        let open_point = MultiPoint::new(vars.clone());
        let open_instance = OpenInstance::new(witness_commit, open_point.clone(), w_eval);

        // Get claimed unverfied evals of each matrix in (rx, open_point), to
        // be checked later as one of the instances produced in this reduction.
        let (matrix_evals, []) = transcript.receive_message(|proof| proof.matrix_evals.clone())?;
        let matrix_evals = matrix_evals.map(|x| x.0);
        // Evals M(rx,r) * w(r)
        let products = matrix_evals.clone().map(|m| m * w_eval);
        let r_eq = r_eq.eval_as_eq(&open_point);
        let ux_eval = eval_ux(&vars, u, &public_inputs);
        let input_selector = eval_input_selector(&open_point, public_inputs.len());
        let evals = LinearizedMles::new(products, r_eq, w_eval, ux_eval, input_selector);

        let chall = SingleChall(chall);
        let checks = sumcheck_verifier.check_evals_at_r(evals, eval, &chall);
        if !checks {
            return Err(crate::Error::EvalCheck);
        }

        // rx was given by the instance, and the second dimension results from sumcheck.
        let point = [rx, MultiPoint::new(vars)];
        Ok((
            BatchMatrixEvalInstance {
                matrix_evals,
                point,
            },
            open_instance,
        ))
    }
}
