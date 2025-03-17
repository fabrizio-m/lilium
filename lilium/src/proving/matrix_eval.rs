use crate::{
    circuit_key::{CircuitKey, KeySparkStructure},
    instances::matrix_eval::BatchMatrixEvalInstance,
    Error,
};
use ark_ff::Field;
use commit::{CommmitmentScheme2, OpenInstance};
use spark::committed_spark::{CommittedSpark, CommittedSparkInstance, CommittedSparkProof};
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::{
    protocols::{Protocol, Reduction},
    MessageGuard, TranscriptGuard,
};

// type SparkProof<F> = sumcheck::sumcheck::Proof<F, SparkEvalCheck<2>>;
// type SparkVerifier<F> = SumcheckVerifier<F, SparkEvalCheck<2>>;

impl<F: Field, T: Duplex<F>, C, CS: CommmitmentScheme2<F>, const IO: usize, const S: usize>
    CircuitKey<F, T, C, CS, IO, S>
{
    /*fn prove_matrix_evals(
        &self,
        instance: BatchMatrixEvalInstance<F, IO>,
    ) -> Result<MatrixEvalProof<F, CS, IO>, Error> {
        let vars = self.ccs_structure.vars();
        let mut transcript = self.transcript.instanciate();
        let prover = SumcheckProver::<F, SparkEvalCheck<2>>::new(vars);
        let mut proofs = Vec::with_capacity(IO);

        let [c1, c2, c3] = transcript
            .send_message(&instance)
            .map_err(Error::TranscriptError)?;
        let challenges = SparkChallenges::new(c1, c2, c3);
        let zero_check_point = MultiPoint::new(transcript.point().map_err(Error::TranscriptError)?);
        let r = MultiPoint::new(transcript.point().map_err(Error::TranscriptError)?);

        for i in 0..IO {
            let structure = &self.spark_structure[i];
            let instance = &instance.matrices[i];
            let MatrixEvalInstance { point, eval: _ } = instance;
            let mle = spark::evals::SparkEval::evals(
                structure,
                point.clone(),
                challenges,
                zero_check_point.clone(),
            );
            let proof = prover.prove(&r, mle, &challenges);
            proofs.push(proof);
        }
        let spark_proofs: [SparkProof<F>; IO] = proofs.try_into().unwrap();
        let commits = &self.spark_commitments;
        let scheme = &self.committment_scheme;
        let open_proofs = commits.each_ref().map(|commits| {
            let open = commits.eval(scheme, &r);
            open
        });
        Ok(MatrixEvalProof {
            spark_proofs,
            open_proofs,
        })
    }*/
    /*fn verify_matrix_evals(
        &self,
        instance: BatchMatrixEvalInstance<F, IO>,
        proof: MatrixEvalProof<F, CS, IO>,
    ) -> Result<bool, Error> {
        let vars = self.ccs_structure.vars();
        let mut transcript = self.transcript.instanciate();

        let [c1, c2, c3] = transcript
            .send_message(&instance)
            .map_err(Error::TranscriptError)?;
        let challenges = SparkChallenges::new(c1, c2, c3);
        let zero_check_point = MultiPoint::new(transcript.point().map_err(Error::TranscriptError)?);
        let r = MultiPoint::new(transcript.point().map_err(Error::TranscriptError)?);

        let mut eval_instances = instance.matrices.into_iter();
        let MatrixEvalProof {
            spark_proofs,
            open_proofs,
        } = proof;
        let mut spark_proofs = spark_proofs.into_iter();
        let mut open_proofs = open_proofs.into_iter();
        let verifier = SumcheckVerifier::<F, SparkEvalCheck<2>>::new(vars);
        let mut eval_checks = vec![];
        // verifiying sumcheck
        for _ in 0..IO {
            let MatrixEvalInstance { point, eval } = eval_instances.next().unwrap();
            let proof = spark_proofs.next().unwrap();
            let verifies = verifier.verify(&r, proof, eval);
            match verifies {
                Ok(check) => eval_checks.push((check, point)),
                Err(_) => return Ok(false),
            }
        }
        // verifiying commitment openings
        let scheme = &self.committment_scheme;
        let mut eval_checks = eval_checks.into_iter();
        let mut spark_commitments = self.spark_commitments.iter();
        let zero_eq_eval = zero_check_point.eval_as_eq(&r);
        for _ in 0..IO {
            let (check, spark_point) = eval_checks.next().unwrap();
            let (open_proof, evals) = open_proofs.next().unwrap();
            let spark_commitment: &CommittedStructure<_, _, _> = spark_commitments.next().unwrap();
            let spark_point_evals: [F; 2] = spark_point.map(|x| x.eval_as_eq(&r));
            let small_evals =
                SparkEval::<Option<F>, 2>::small_evals(zero_eq_eval, spark_point_evals);
            let evals = evals.merge_small_evals(small_evals);
            let verifies = spark_commitment.verify(scheme, &r, open_proof, evals.clone());
            if !verifies {
                return Ok(false);
            }
            let verifies = verifier.check_evals_at_r(evals, check, &challenges);
            if !verifies {
                return Ok(false);
            }
        }
        Ok(true)
    }*/
}
struct MatrixEvalProof<F, CS, const IO: usize>
where
    F: Field,
    CS: CommmitmentScheme2<F>,
{
    spark_proofs: [CommittedSparkProof<F, CS, 2>; IO],
    open_proofs: [CS::OpenProof; IO],
}

struct MatrixEvalProtocol<F, K, CS, const IO: usize>(PhantomData<(F, K, CS)>);

impl<K, F, CS, const IO: usize> Protocol<F> for MatrixEvalProtocol<F, K, CS, IO>
where
    F: Field,
    //TODO: check
    CS: CommmitmentScheme2<F> + 'static,
    K: KeySparkStructure<F, CS, IO>,
{
    type Instance = BatchMatrixEvalInstance<F, IO>;

    type Key = K;

    type Proof = MatrixEvalProof<F, CS, IO>;

    type Error = Error<F, CS>;

    fn transcript_pattern(
        builder: transcript::TranscriptBuilder<F>,
    ) -> transcript::TranscriptBuilder<F> {
        let builder = builder.round::<Self::Instance, 0>();
        let builder = [(); IO].iter().fold(builder, |builder, _| {
            builder.add_reduction_patter::<CommittedSpark<F, CS, 2>>()
        });
        let builder = [(); IO]
            .iter()
            .fold(builder, |builder, _| builder.add_protocol_patter::<CS>());
        builder
    }

    fn verify<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::Instance>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<(), Self::Error> {
        let (instance, []) = transcript.unwrap_guard(instance)?;

        let BatchMatrixEvalInstance {
            matrix_evals,
            point,
        } = instance;

        let spark_proofs = transcript.receive_message_delayed(|proof| proof.spark_proofs.clone());
        let mut spark_proofs = spark_proofs.transpose().into_iter();

        let mut open_instances = [(); IO].map(|_| None);
        for i in 0..IO {
            let eval = matrix_evals[i];
            let instance = CommittedSparkInstance::new(point.clone(), eval);
            let instance = MessageGuard::new(instance);

            let proof = spark_proofs.next().unwrap();

            let key = &key.spark_keys()[i];
            let reduced =
                CommittedSpark::verify_reduction(key, instance, transcript.new_guard(proof))?;

            open_instances[i] = Some(reduced);
        }
        let open_instances: [OpenInstance<F, CS::Commitment>; IO] =
            open_instances.map(Option::unwrap);

        // verifiying commitment openings
        let open_proofs: [MessageGuard<CS::OpenProof>; IO] = transcript
            .receive_message_delayed(|proof| proof.open_proofs.clone())
            .transpose();
        let mut open_proofs = open_proofs.into_iter();

        // TODO: they can't be batched by the available reduction, as they are over
        // different point.
        // Should be batched, but also spark will be batched making this not an issue.
        for instance in open_instances {
            let scheme = key.pcs();
            let instance = MessageGuard::new(instance);
            let proof: MessageGuard<CS::OpenProof> = open_proofs.next().unwrap();

            let verifies = CS::verify(scheme, instance, transcript.new_guard(proof));
            verifies.map_err(Error::Pcs)?;
        }
        Ok(())
    }

    fn prove(_instance: Self::Instance) -> Self::Proof {
        todo!()
    }
}
