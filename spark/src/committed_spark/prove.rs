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
    eq,
    polynomials::{Evals, MultiPoint},
    sumcheck::{CommitType, EvalKind, SumcheckProver},
};
use transcript::{messages::SingleElement, Transcript};

pub struct ProverOutput<F: Field, C: CommmitmentScheme<F>, const D: usize> {
    pub open_instance: OpenInstance<F, C::Commitment>,
    pub witness: Vec<F>,
    pub proof: CommittedSparkProof<F, C, D>,
}

type Commitments<C, const D: usize> = ([C; D], [[C; 2]; D]);

impl<F: Field, C: CommmitmentScheme<F>, const D: usize> CommittedSpark<F, C, D> {
    fn mles<S>(
        &self,
        points: [MultiPoint<F>; D],
        transcript: &mut Transcript<F, S>,
        scheme: &C,
    ) -> (
        Vec<SparkEval<F, D>>,
        SparkChallenges<F>,
        Commitments<C::Commitment, D>,
    )
    where
        S: Duplex<F>,
        C: 'static,
    {
        let eqs = points.clone().map(|point| eq::eq(&point));
        let mut eqs = eqs.iter();
        let eq_lookups = self.structure.dimensions.each_ref().map(|structure| {
            let mut lookups = Vec::with_capacity(structure.lookups.len());
            let eq = eqs.next().unwrap();
            for i in structure.lookups.iter() {
                lookups.push(eq[*i]);
            }
            lookups
        });
        let eq_lookup_commitments = eq_lookups
            .each_ref()
            .map(|lookups| scheme.commit_mle(lookups));
        let [c1, c2] = transcript.send_message(&eq_lookup_commitments).unwrap();

        let zero_check_point = MultiPoint::new(transcript.point().unwrap());

        // The second one is not used and can be set to zero.
        let challenges = SparkChallenges::new(c1, F::zero(), c2);
        let mles = SparkEval::evals(
            &self.structure,
            points,
            challenges,
            zero_check_point.clone(),
        );

        let mut fraction_commitments = [(); D].map(|_| None);

        for (i, commitments) in fraction_commitments.iter_mut().enumerate() {
            let index = SparkIndex::Dimension(i, DimensionIndex::Lookup(LookupIdx::Frac1));
            let f1: Vec<F> = mles.iter().map(|evals| *evals.index(index)).collect();
            let f1_commit = scheme.commit_mle(&f1);
            let index = SparkIndex::Dimension(i, DimensionIndex::Lookup(LookupIdx::Frac2));
            let f2: Vec<F> = mles.iter().map(|evals| *evals.index(index)).collect();
            let f2_commit = scheme.commit_mle(&f2);
            *commitments = Some([f1_commit, f2_commit]);
        }

        let fraction_commitments = fraction_commitments.map(Option::unwrap);

        let [c3] = transcript.send_message(&fraction_commitments).unwrap();

        let challenges = SparkChallenges::new(c1, c3, c2);

        let commitments = (eq_lookup_commitments, fraction_commitments);
        (mles, challenges, commitments)
    }

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
        let [] = transcript.send_message(&instance).unwrap();
        // The eval could be used to double check result.
        let CommittedSparkInstance { point, eval: _ } = instance;

        let sumcheck_prover = SumcheckProver::<F, SparkEvalCheck<D>>::new(vars);

        let (mles, challenges, commitments) = self.mles(point, transcript, scheme);
        let sumcheck::sumcheck::ProverOutput {
            point: r,
            proof: sumcheck_proof,
            evals,
        } = sumcheck_prover
            .prove(transcript, mles.clone(), &challenges)
            .unwrap();

        let (eq_lookup_commitments, fraction_lookup_commitments) = commitments;
        let multi_commit = {
            let commitments = (0..D)
                .flat_map(|i| {
                    let [f1, f2] = fraction_lookup_commitments[i].clone();
                    let elc = eq_lookup_commitments[i].clone();
                    [f1, f2, elc]
                })
                .collect();
            self.committed_structure.instance_commit(commitments)
        };

        let structure_evals = {
            let kinds = SparkEval::<F, D>::kinds().flatten_vec();
            let evals = evals.clone().flatten_vec();
            let mut evals = kinds
                .into_iter()
                .zip(evals)
                .filter_map(|(kind, eval)| match kind {
                    EvalKind::Committed(CommitType::Structure) => Some(eval),
                    _ => None,
                });
            let per_dimension = [(); D].map(|_| [evals.next(), evals.next()].map(Option::unwrap));
            let shared = [evals.next(), evals.next()].map(Option::unwrap);
            assert!(evals.next().is_none());
            (per_dimension, shared)
        };

        let instance_evals = {
            let kinds = SparkEval::<F, D>::kinds().flatten_vec();
            let evals = evals.flatten_vec();
            let mut evals = kinds
                .into_iter()
                .zip(evals)
                .filter_map(|(kind, eval)| match kind {
                    EvalKind::Committed(CommitType::Instance) => Some(eval),
                    _ => None,
                });
            let instance_evals = [(); D].map(|_| [(); 3].map(|_| evals.next().unwrap()));
            assert!(evals.next().is_none());
            instance_evals
        };

        {
            let instance_evals = instance_evals.map(|d| d.map(SingleElement));
            let [] = transcript.send_message(&instance_evals).unwrap();

            let (per_dimension, shared) = structure_evals;
            let per_dimension = per_dimension.map(|d| d.map(SingleElement));
            let shared = shared.map(SingleElement);
            let structure_evals = (per_dimension, shared);
            let [] = transcript.send_message(&structure_evals).unwrap();
        }

        let instance = self
            .committed_structure
            .open_instance(multi_commit, mles.to_vec(), r);
        let (open_instance, witness) = self.committed_structure.prove(instance, &mles, transcript);

        let proof = CommittedSparkProof {
            eq_lookup_commitments,
            fraction_lookup_commitments,
            sumcheck_proof,
            structure_evals,
            instance_evals,
        };

        ProverOutput {
            open_instance,
            witness,
            proof,
        }
    }
}
