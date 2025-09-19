use crate::instances::{
    lcs::{
        key::LcsProvingKey,
        sumcheck_argument::{LcsMles, LcsSumcheck, SingleChall},
        LcsInstance,
    },
    linearized::LinearizedInstance,
};
use ark_ff::Field;
use ccs::witness::LinearCombinations;
use commit::{CommmitmentScheme, OpenInstance};
use sponge::sponge::Duplex;
use sumcheck::{
    eq,
    polynomials::MultiPoint,
    sumcheck::{Proof, ProverOutput, Sum, SumcheckProver},
};
use transcript::{MessageGuard, Transcript};

// type InstanceWitness = ()

struct ReducedInstanceWitness<F, C, const I: usize, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub linearized_instance: LinearizedInstance<F, C, I, IO, 4>,
    pub linearized_witness: Vec<F>,
    pub open_instance: OpenInstance<F, C::Commitment>,
    pub open_witness: Vec<F>,
    pub reduction_proof: Proof<F, LcsSumcheck<F, IO, 4>>,
}

impl<F: Field, C: CommmitmentScheme<F>, const IO: usize> LcsProvingKey<F, C, IO> {
    fn reduce_instance_witness<S, const I: usize>(
        key: LcsProvingKey<F, C, IO>,
        instance: LcsInstance<F, C, I>,
        witness: Vec<F>,
        transcript: &mut Transcript<F, S>,
    ) -> ReducedInstanceWitness<F, C, I, IO>
    where
        S: Duplex<F>,
        C: 'static,
    {
        //TODO: handle
        let [sumcheck_chall] = transcript.send_message(&instance).unwrap();

        // Get challenge point for sumcheck's zero-check.
        //TODO: handle
        let r_eq = transcript.point().unwrap();
        let r_eq = MultiPoint::new(r_eq);

        let sumcheck_instance = MessageGuard::new(Sum(F::zero()));

        //TODO: from key
        let vars = 4;
        //TODO: add selectors
        //TODO: create once and store in key.
        let sumcheck_prover: SumcheckProver<F, LcsSumcheck<F, IO, 4>> = SumcheckProver::new(vars);

        let challs = SingleChall::from(sumcheck_chall);
        // let mle: Vec<LcsMles<F, IO, 4>> = vec![];
        let inputs = &instance.public_inputs;
        let mles = fill_mles(&key.mles, &key.linear_combinations, inputs, witness, r_eq);

        //TODO: handle
        let ProverOutput {
            point,
            proof,
            evals,
        } = sumcheck_prover.prove(transcript, mles, &challs).unwrap();
        let evals: LcsMles<F, IO, 4> = evals;

        let linearized_instance: LinearizedInstance<F, C, I, IO, 4> = LinearizedInstance {
            witness_commit: instance.witness_commit,
            u: F::one(),
            public_inputs: instance.public_inputs,
            rx: point,
            products: *evals.products(),
            selector_evals: *evals.gate_selectors(),
        };
        todo!()
    }
}

fn fill_mles<F, const IO: usize>(
    structure: &[LcsMles<F, IO, 4>],
    linear_combinations: &LinearCombinations<IO>,
    inputs: &[F],
    witness: Vec<F>,
    r_eq: MultiPoint<F>,
) -> Vec<LcsMles<F, IO, 4>>
where
    F: Field,
{
    let mut mles = structure.to_vec();
    let mut combinations = linear_combinations.compute(&witness);
    let r_eq = eq::eq(&r_eq);

    for i in 0..mles.len() {
        let products: [F; IO] = combinations.next().unwrap();
        let r_eq = r_eq[i];
        let inputs = inputs.get(i).cloned();
        let w = witness[i];
        mles[i].set_instance_witness_evals(products, r_eq, w, inputs);
    }
    mles
}
