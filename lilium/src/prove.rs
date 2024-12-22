use crate::{
    circuit_key::CircuitKey,
    instance::{BatchMatrixEvalInstance, MatrixEvalInstance},
};
use ark_ff::Field;
use ccs::circuit::Circuit;
use commit::CommmitmentScheme;
use spark::{challenges::SparkChallenges, evals::SparkEval, spark::SparkEvalCheck};
use sumcheck::{polynomials::MultiPoint, sumcheck::SumcheckProver};

type SparkProof<F> = sumcheck::sumcheck::Proof<F, SparkEvalCheck<2>>;

impl<
        F: Field,
        C: Circuit<F, IN, OUT, PRIV_OUT>,
        CS: CommmitmentScheme<F>,
        const IN: usize,
        const OUT: usize,
        const PRIV_OUT: usize,
        const IO: usize,
        const S: usize,
    > CircuitKey<F, C, CS, IN, OUT, PRIV_OUT, IO, S>
{
    fn prove_matrix_evals(
        &self,
        instance: BatchMatrixEvalInstance<F, IO>,
    ) -> MatrixEvalProof<F, CS, IO> {
        let vars = self.ccs_structure.vars();
        let prover = SumcheckProver::<F, SparkEvalCheck<2>>::new(vars);
        let mut proofs = Vec::with_capacity(IO);
        //TODO
        let challenges = SparkChallenges::new(F::one(), F::one(), F::one());
        //TODO
        let zero_check_point = MultiPoint::new(vec![F::one(); 8]);
        //TODO
        let r = MultiPoint::new(vec![F::one(); 8]);
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
        MatrixEvalProof {
            spark_proofs,
            open_proofs,
        }
    }
}
struct MatrixEvalProof<F, CS, const IO: usize>
where
    F: Field,
    CS: CommmitmentScheme<F>,
{
    spark_proofs: [SparkProof<F>; IO],
    open_proofs: [(Vec<CS::OpenProof>, SparkEval<Option<F>, 2>); IO],
}
