use crate::{
    challenges::SparkChallenges,
    committed_spark::{CommittedSpark, CommittedSparkInstance, CommittedSparkProof},
    evals::{DimensionIndex, SparkEval, SparkIndex},
    mvlookup::LookupIdx,
    spark::SparkEvalCheck,
};
use ark_ff::Field;
use commit::{CommmitmentScheme, OpenInstance};
use sponge::sponge::Duplex;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::SumcheckProver,
};
use transcript::Transcript;

pub struct ProverOutput<F: Field, C: CommmitmentScheme<F>, const D: usize> {
    pub open_instance: OpenInstance<F, C::Commitment>,
    pub witness: Vec<F>,
    pub proof: CommittedSparkProof<F, C, D>,
}

impl<F: Field, C: CommmitmentScheme<F>, const D: usize> CommittedSpark<F, C, D> {
    pub fn prove<S: Duplex<F>>(
        &self,
        transcript: &mut Transcript<F, S>,
        instance: CommittedSparkInstance<F, D>,
        scheme: &C,
    ) -> ProverOutput<F, C, D>
    where
        C: 'static,
    {
        let vars = self.committed_structure.vars();
        let [c1, c2, c3] = transcript.send_message(&instance).unwrap();
        // The eval could be used to double check result.
        let CommittedSparkInstance { point, eval: _ } = instance;

        let challenges = SparkChallenges::new(c1, c2, c3);
        let zero_check_point = MultiPoint::new(transcript.point().unwrap());

        let sumcheck_prover = SumcheckProver::<F, SparkEvalCheck<D>>::new(vars);

        //TODO: memory use may be improved.
        let mles = SparkEval::evals(&self.structure, point, challenges, zero_check_point);
        let sumcheck::sumcheck::ProverOutput {
            point: r,
            proof: sumcheck_proof,
            ..
        } = sumcheck_prover
            .prove(transcript, mles.clone(), &challenges)
            .unwrap();
        let multi_commit = {
            let mut instance_mles: Vec<Vec<F>> = vec![vec![F::zero(); mles.len()]; D * 3];

            for i in 0..D {
                let indices = [
                    DimensionIndex::Lookup(LookupIdx::Frac1),
                    DimensionIndex::Lookup(LookupIdx::Frac2),
                    DimensionIndex::EqLookup,
                ]
                .map(|d| SparkIndex::Dimension(i, d));
                for j in 0..3 {
                    let index = indices[j];
                    for (e, mles) in instance_mles[3 * i + j].iter_mut().zip(mles.iter()) {
                        *e = *mles.index(index);
                    }
                }
            }
            let mles: Vec<&[F]> = instance_mles.iter().map(|x| x.as_slice()).collect();
            self.committed_structure.commit(scheme, &mles)
        };

        let instance = self
            .committed_structure
            .open_instance(multi_commit, mles.to_vec(), r);
        let committed_evals = instance.clone();
        let (open_instance, witness) = self.committed_structure.prove(instance, &mles, transcript);

        let proof = CommittedSparkProof {
            sumcheck_proof,
            committed_evals,
        };

        ProverOutput {
            open_instance,
            witness,
            proof,
        }
    }
}
