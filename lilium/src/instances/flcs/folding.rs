use crate::flcs::{
    sumcheck_reduction::{ConstraintCombinationChallenge, LcsMles, LcsSumcheck, LcsSumfold},
    FoldableLcsInstance,
};
use ark_ff::Field;
use ccs::{structure::Exp, witness::LinearCombinations};
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use std::{iter::repeat, marker::PhantomData, rc::Rc};
use sumcheck::{
    folding::{SumFold, SumFoldInstance, SumFoldProof, SumFoldProverOutput, ZeroFold},
    zerocheck::ZeroCheckMles,
};
use transcript::{
    protocols::Reduction, MessageGuard, Transcript, TranscriptBuilder, TranscriptGuard,
};

pub struct LcsFolding<F, C, const IO: usize> {
    _phantom: PhantomData<(F, C)>,
}

pub struct LcsFoldingKey<F: Field, const IO: usize> {
    // vars: usize,
    zerofold: ZeroFold<F, LcsSumfold<F, IO, 4>>,
    structure: Rc<Vec<ZeroCheckMles<F, LcsMles<F, IO, 4>>>>,
    linear_combinations: Rc<LinearCombinations<IO>>,
}

impl<F, C, const IO: usize> Reduction<F> for LcsFolding<F, C, IO>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = [FoldableLcsInstance<F, C, IO>; 2];

    type B = FoldableLcsInstance<F, C, IO>;

    type Key = LcsFoldingKey<F, IO>;

    type Proof = SumFoldProof<F>;

    type Error = ();

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder
            .round::<F, Self::A, 0>()
            .add_reduction_patter::<F, SumFold<F, _>>(key.zerofold.sumfold_key())
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        // TODO: handle.
        let (instances, []): ([FoldableLcsInstance<F, C, IO>; 2], _) =
            transcript.unwrap_guard(instance).unwrap();

        let sums = instances.each_ref().map(|instance| instance.sum);
        let sumfold_instance = MessageGuard::new(SumFoldInstance::new(sums));
        // TODO: handle.
        let (sum, folder) =
            SumFold::verify_reduction(key.zerofold.sumfold_key(), sumfold_instance, transcript)
                .unwrap();
        let [a, b] = instances;
        let folded_instance = a.fold(b, folder, sum.0);
        Ok(folded_instance)
    }
}

impl<F: Field, const IO: usize> LcsFoldingKey<F, IO> {
    pub fn new(
        gates: Vec<Vec<Exp<usize>>>,
        vars: usize,
        structure: Rc<Vec<ZeroCheckMles<F, LcsMles<F, IO, 4>>>>,
        linear_combinations: Rc<LinearCombinations<IO>>,
    ) -> Self {
        let function = LcsSumcheck::<F, IO, 4>::new(gates, false);
        let zerofold = ZeroFold::new(LcsSumfold::from(function), vars);
        Self {
            zerofold,
            structure,
            linear_combinations,
        }
    }

    pub fn fold<C, S>(
        &self,
        instances: [FoldableLcsInstance<F, C, IO>; 2],
        witnesses: [Vec<F>; 2],
        transcript: &mut Transcript<F, S>,
    ) -> (FoldableLcsInstance<F, C, IO>, Vec<F>, SumFoldProof<F>)
    where
        C: CommmitmentScheme<F>,
        S: Duplex<F>,
    {
        let (w1, w2) = {
            let [w1, w2] = witnesses.each_ref();
            let structure = &self.structure;
            let combinations = &self.linear_combinations;
            let w1 = fill_mles(structure, combinations, &instances[0].public_inputs, w1);
            let w2 = fill_mles(structure, combinations, &instances[1].public_inputs, w2);
            (w1, w2)
        };
        let sums = SumFoldInstance::new(instances.each_ref().map(|instance| instance.sum));
        let powers = instances
            .each_ref()
            .map(|instance| instance.zerocheck_powers.clone());
        // dummy value as it won't be used in folding.
        let challenges = ConstraintCombinationChallenge::from(F::zero());
        let SumFoldProverOutput {
            instance: _,
            folded_witness: _,
            proof,
            folder,
            sum,
        } = self
            .zerofold
            .fold_zerocheck(w1, &w2, sums.into(), powers, challenges, transcript);

        let [inst1, inst2] = instances;
        let instance = inst1.fold(inst2, folder, sum);

        let [mut w1, w2] = witnesses;
        folder.fold_vector(&mut w1, &w2);
        let witness = w1;

        (instance, witness, proof)
    }
}

fn fill_mles<F, const IO: usize>(
    structure: &[ZeroCheckMles<F, LcsMles<F, IO, 4>>],
    linear_combinations: &LinearCombinations<IO>,
    inputs: &[F],
    witness: &[F],
) -> Vec<LcsMles<F, IO, 4>>
where
    F: Field,
{
    let mut mles: Vec<_> = structure.iter().map(|e| *e.inner()).collect();
    let combinations = linear_combinations.compute(witness);
    let combinations = combinations.chain(repeat([F::zero(); IO])).take(mles.len());

    for (i, combination) in combinations.enumerate() {
        let products: [F; IO] = combination;
        let inputs = inputs.get(i).cloned();
        let w = witness[i];
        mles[i].set_instance_witness_evals(products, w, inputs);
    }
    mles
}
