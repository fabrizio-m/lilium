use crate::{
    challenges::SparkChallenges,
    committed_spark::CommittedSparkInstance,
    spark2::{
        evals::SparkOpen, sumcheck_argument::SparkOpenSumcheck, CommittedSpark, CommittedSparkProof,
    },
};
use ark_ff::{batch_inversion, Field};
use commit::{CommmitmentScheme, OpenInstance};
use sponge::sponge::Duplex;
use sumcheck::{
    eq,
    polynomials::{Evals, MultiPoint},
    sumcheck::{CommitType, EvalKind, SumcheckFunction, SumcheckProver},
};
use transcript::{messages::SingleElement, Transcript};

pub struct ProverOutput<F: Field, C: CommmitmentScheme<F>, const D: usize> {
    pub open_instance: OpenInstance<F, C::Commitment>,
    pub witness: Vec<F>,
    pub proof: CommittedSparkProof<F, C, D>,
}

type Commitments<C, const N: usize> = ([C; N], [C; N]);

impl<F: Field, C: CommmitmentScheme<F>, const N: usize> CommittedSpark<F, C, N> {
    fn mles<S>(
        &self,
        points: [MultiPoint<F>; N],
        transcript: &mut Transcript<F, S>,
        scheme: &C,
    ) -> (
        Vec<SparkOpen<F, N>>,
        SparkChallenges<F>,
        Commitments<C::Commitment, N>,
    )
    where
        S: Duplex<F>,
        C: 'static,
    {
        let eqs = points.clone().map(|point| eq::eq(&point));

        let eq_lookup_commitments: [C::Commitment; N] = (0..N)
            .map(|i| {
                let eq = &eqs[i];
                let eq: [F; 256] = eq.clone().try_into().unwrap();

                let evals: Vec<u8> = self
                    .mle
                    .addresses
                    .iter()
                    .map(|segments| segments[i])
                    .collect();

                scheme.commit_small_set(&evals, eq)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let [c1, c2] = transcript.send_message(&eq_lookup_commitments).unwrap();
        let lookup_challenge = c1;
        let compression_challenge = c2;

        let zero_check_point = MultiPoint::new(transcript.point().unwrap());

        let mles = SparkOpen::evals(
            &self.major_structure,
            &self.mle,
            points,
            &zero_check_point,
            lookup_challenge,
            compression_challenge,
        );

        let mut inverse_commitments = [(); N].map(|_| None);

        for (i, commitments) in inverse_commitments.iter_mut().enumerate() {
            let evals: Vec<u8> = self
                .mle
                .addresses
                .iter()
                .map(|segments| segments[i])
                .collect();

            let eq = &eqs[i];
            let eq: [F; 256] = eq.clone().try_into().unwrap();
            let mut inverses = eq;

            for (i, eq) in inverses.iter_mut().enumerate() {
                *eq = F::from(i as u8) * compression_challenge + *eq + lookup_challenge
            }
            batch_inversion(&mut inverses);

            *commitments = Some(scheme.commit_small_set(&evals, inverses));
        }

        let inverse_commitments = inverse_commitments.map(Option::unwrap);

        let [c3] = transcript.send_message(&inverse_commitments).unwrap();

        let challenges = SparkChallenges::new(c1, c3, c2);
        let commitments = (eq_lookup_commitments, inverse_commitments);

        (mles, challenges, commitments)
    }

    pub fn prove<S: Duplex<F>>(
        &self,
        transcript: &mut Transcript<F, S>,
        instance: CommittedSparkInstance<F, N>,
        scheme: &C,
    ) -> ProverOutput<F, C, N>
    where
        C: 'static,
    {
        let vars = self.committed_structure.vars();
        let [] = transcript.send_message(&instance).unwrap();
        // The eval could be used to double check result.
        let CommittedSparkInstance { point, eval: _ } = instance;

        //TODO: store
        let sumcheck_prover = SumcheckProver::new_symbolic(vars, &SparkOpenSumcheck);

        let (mles, challenges, commitments) = self.mles(point, transcript, scheme);
        let sumcheck::sumcheck::ProverOutput {
            point: r,
            proof: sumcheck_proof,
            evals,
        } = sumcheck_prover
            .prove_symbolic(transcript, mles.clone(), &challenges)
            .unwrap();

        let (eq_lookup_commitments, fraction_lookup_commitments) = commitments;
        let multi_commit = {
            let commitments = (0..N)
                .flat_map(|i| {
                    let inverse = fraction_lookup_commitments[i].clone();
                    let elc = eq_lookup_commitments[i].clone();
                    [elc, inverse]
                })
                .collect();
            self.committed_structure.instance_commit(commitments)
        };

        let kinds: SparkOpen<EvalKind, N> = <SparkOpenSumcheck<N> as SumcheckFunction<F>>::KINDS;

        let structure_evals = {
            let kinds = kinds.flatten_vec();
            let evals = evals.flatten_vec();
            let mut evals = kinds
                .into_iter()
                .zip(evals)
                .filter_map(|(kind, eval)| match kind {
                    EvalKind::Committed(CommitType::Structure) => Some(eval),
                    _ => None,
                });
            let per_dimension = [(); N].map(|_| evals.next().unwrap());
            let shared = evals.next().unwrap();
            assert!(evals.next().is_none());
            (per_dimension, shared)
        };

        let instance_evals = {
            let kinds = kinds.flatten_vec();
            let evals = evals.flatten_vec();
            let mut evals = kinds
                .into_iter()
                .zip(evals)
                .filter_map(|(kind, eval)| match kind {
                    EvalKind::Committed(CommitType::Instance) => Some(eval),
                    _ => None,
                });
            let instance_evals = [(); N].map(|_| [(); 2].map(|_| evals.next().unwrap()));
            assert!(evals.next().is_none());
            instance_evals
        };

        {
            let instance_evals = instance_evals.map(|d| d.map(SingleElement));
            let [] = transcript.send_message(&instance_evals).unwrap();

            let (per_dimension, shared) = structure_evals;
            let per_dimension = per_dimension.map(SingleElement);
            let shared = SingleElement(shared);
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
