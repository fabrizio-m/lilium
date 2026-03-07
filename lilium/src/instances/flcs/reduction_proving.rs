use crate::instances::{
    flcs::{
        key::FlcsReductionKey, reduction::FlcsReductionProof, sumcheck_reduction::LcsMles,
        FoldableLcsInstance,
    },
    linearized::LinearizedInstance,
};
use ark_ff::Field;
use ccs::witness::LinearCombinations;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use sumcheck::{
    sumcheck::ProverOutput,
    zerocheck::{CompactPowers, ZeroCheckMles},
};
use transcript::{messages::SingleElement, Transcript};

pub struct ReducedInstanceWitness<F, C, const I: usize, const IO: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    pub linearized_instance: LinearizedInstance<F, C, IO, 4>,
    pub linearized_witness: Vec<F>,
    pub reduction_proof: FlcsReductionProof<F, IO>,
}

impl<F: Field, const IO: usize> FlcsReductionKey<F, IO> {
    pub fn reduce_foldable_instance_witness<C, S, const I: usize>(
        &self,
        instance: FoldableLcsInstance<F, C, I>,
        witness: Vec<F>,
        transcript: &mut Transcript<F, S>,
    ) -> ReducedInstanceWitness<F, C, I, IO>
    where
        S: Duplex<F>,
        C: CommmitmentScheme<F> + 'static,
    {
        //TODO: handle
        let [sumcheck_chall] = transcript.send_message(&instance).unwrap();

        let sumcheck_prover = &self.sumcheck_prover;

        let challs = sumcheck_chall.into();

        let inputs = &instance.public_inputs;
        let mles = fill_mles(
            &self.structure,
            &self.linear_combinations,
            inputs,
            &instance.zerocheck_powers,
            &witness,
        );

        //TODO: handle
        let ProverOutput {
            point,
            proof,
            evals,
        } = sumcheck_prover
            .prove_zerocheck(instance.zerocheck_powers, transcript, mles, &challs)
            .unwrap();
        let evals: ZeroCheckMles<F, LcsMles<F, IO, 4>> = evals;

        let reduction_proof = FlcsReductionProof::new(
            proof,
            *evals.inner().gate_selectors(),
            *evals.inner().w(),
            *evals.inner().products(),
        );

        let linearized_instance: LinearizedInstance<F, C, IO, 4> = LinearizedInstance {
            witness_commit: instance.witness_commit,
            witness_eval: *evals.inner().w(),
            rx: point,
            products: *evals.inner().products(),
            selector_evals: *evals.inner().gate_selectors(),
        };

        let selector_evals = linearized_instance.selector_evals.map(SingleElement);
        //TODO: Handle
        let [] = transcript.send_message(&selector_evals).unwrap();
        let witness_eval = SingleElement(*evals.inner().w());
        let [] = transcript.send_message(&witness_eval).unwrap();
        //TODO: Handle
        let products = linearized_instance.products.map(SingleElement);
        let [] = transcript.send_message(&products).unwrap();

        let linearized_witness = witness;
        ReducedInstanceWitness {
            linearized_instance,
            linearized_witness,
            reduction_proof,
        }
    }
}

fn fill_mles<F, const IO: usize>(
    structure: &[ZeroCheckMles<F, LcsMles<F, IO, 4>>],
    linear_combinations: &LinearCombinations<IO>,
    inputs: &[F],
    powers: &CompactPowers<F>,
    witness: &[F],
) -> Vec<ZeroCheckMles<F, LcsMles<F, IO, 4>>>
where
    F: Field,
{
    let mut mles = structure.to_vec();
    let mut combinations = linear_combinations.compute(witness);
    let powers = powers.eval_over_domain().into_iter();

    for (i, power) in powers.enumerate() {
        let products: [F; IO] = combinations.next().unwrap_or([F::zero(); IO]);
        let mut inner = *mles[i].inner();
        let inputs = inputs.get(i).cloned();
        let w = witness[i];
        inner.set_instance_witness_evals(products, w, inputs);
        mles[i] = ZeroCheckMles::new(power, inner);
    }
    mles
}
