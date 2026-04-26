use crate::{instances::matrix_eval::BatchMatrixEvalInstance, Error};
use ark_ff::Field;
use commit::batching::multipoint::{self, BatchingProof, MultipointBatching};
use commit::{CommmitmentScheme, OpenInstance};
use spark::spark2::flexible::{self, FlexibleSpark};
use sponge::sponge::Duplex;
use std::{marker::PhantomData, rc::Rc};
use sumcheck::polynomials::MultiPoint;
use sumcheck::sumcheck::SumcheckVerifier;
use transcript::{
    protocols::{Protocol, Reduction},
    MessageGuard, Transcript, TranscriptGuard,
};

type ProverResult<T, F, C> = Result<T, Error<F, C>>;

pub struct Key<F: Field, C: CommmitmentScheme<F>, const IO: usize> {
    pub spark_keys: [flexible::FlexibleSpark<F, C>; IO],
    pub pcs: Rc<C>,
    pub batching: SumcheckVerifier<F, MultipointBatching<C, IO>>,
}

fn merge_points<F: Field>(points: [MultiPoint<F>; 2]) -> MultiPoint<F> {
    let [a, b] = points;
    let mut point = a.inner();
    point.extend(b.inner());
    MultiPoint::new(point)
}

impl<F, C, const IO: usize> Key<F, C, IO>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    pub fn new(evals: [Vec<([usize; 2], F)>; IO], pcs: Rc<C>) -> Self {
        assert!(evals[0].len().is_power_of_two());
        let vars = evals[0].len().ilog2() as usize;
        let spark_keys = evals.map(|evals| {
            assert_eq!(vars, evals.len().ilog2() as usize);
            let evals: Vec<(u64, F)> = evals
                .iter()
                .map(|(addr, val)| {
                    let addr = addr[0] as u64 | ((addr[1] as u64) << vars);
                    (addr, *val)
                })
                .collect();
            FlexibleSpark::new(evals, pcs.as_ref())
        });
        let batching = SumcheckVerifier::new_symbolic(MultipointBatching::default(), vars);
        Self {
            spark_keys,
            pcs,
            batching,
        }
    }

    pub(crate) fn prove<S>(
        &self,
        instance: BatchMatrixEvalInstance<F, IO>,
        transcript: &mut Transcript<F, S>,
    ) -> ProverResult<MatrixEvalProof<F, C, IO>, F, C>
    where
        C: 'static,
        S: Duplex<F>,
    {
        let mut proofs = Vec::with_capacity(IO);

        //TODO: handle
        let [] = transcript.send_message(&instance).unwrap();

        // OpenInstance (instance, witness) pairs.
        let mut open_pairs = [(); IO].map(|_| None);
        let point = instance.point;
        let point = merge_points(point);

        for (i, eval) in instance.matrix_evals.iter().enumerate() {
            let point = point.clone();
            let instance = flexible::Instance { point, eval: *eval };
            let flexible::ProverOutput {
                open_instance,
                witness,
                proof,
            } = self.spark_keys[i].prove(transcript, instance, &self.pcs);
            open_pairs[i] = Some((open_instance, witness));
            proofs.push(proof);
        }

        let spark_proofs: [flexible::Proof<F, C>; IO] = proofs.try_into().unwrap();
        let instance = open_pairs
            .each_ref()
            .map(|pair| pair.as_ref().unwrap().0.clone());
        let witness = open_pairs.map(|pair| pair.unwrap().1);
        let multipoint::ProverOutput {
            instance,
            witness,
            proof: batching_proof,
        } = MultipointBatching::prove::<F, S>(instance, witness, transcript);

        let open_proof = self
            .pcs
            .open_prove(instance, &witness, transcript)
            .map_err(Error::Pcs)?;

        Ok(MatrixEvalProof {
            spark_proofs,
            batching_proof,
            open_proof,
        })
    }
}

pub(crate) struct MatrixEvalProtocol<F, CS, const IO: usize>(PhantomData<(F, CS)>);

#[derive(Clone, Debug)]
pub(crate) struct MatrixEvalProof<F, CS, const IO: usize>
where
    F: Field,
    CS: CommmitmentScheme<F>,
{
    spark_proofs: [flexible::Proof<F, CS>; IO],
    batching_proof: BatchingProof<F, CS, IO>,
    open_proof: CS::OpenProof,
}

impl<F, CS, const IO: usize> Protocol<F> for MatrixEvalProtocol<F, CS, IO>
where
    F: Field,
    CS: CommmitmentScheme<F> + 'static,
{
    type Instance = BatchMatrixEvalInstance<F, IO>;

    type Key = Key<F, CS, IO>;

    type Proof = MatrixEvalProof<F, CS, IO>;

    type Error = Error<F, CS>;

    fn transcript_pattern(
        key: &Self::Key,
        builder: transcript::TranscriptBuilder,
    ) -> transcript::TranscriptBuilder {
        builder
            .round::<F, Self::Instance, 0>()
            .repeat::<IO, _>(|builder, i| {
                FlexibleSpark::transcript_pattern(&key.spark_keys[i], builder)
            })
            .add_reduction_patter::<F, MultipointBatching<CS, IO>>(&key.batching)
            .add_protocol_patter::<F, CS>(&key.pcs)
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
        let point = merge_points(point);

        let spark_proofs = transcript.receive_message_delayed(|proof| proof.spark_proofs.clone());
        let mut spark_proofs = spark_proofs.transpose().into_iter();

        let mut open_instances = [(); IO].map(|_| None);
        for i in 0..IO {
            let eval = matrix_evals[i];
            let point = point.clone();
            let instance = flexible::Instance { point, eval };
            let instance = MessageGuard::new(instance);

            let proof = spark_proofs.next().unwrap();

            let key = &key.spark_keys[i];
            let reduced =
                FlexibleSpark::verify_reduction(key, instance, transcript.new_guard(proof))?;

            open_instances[i] = Some(reduced);
        }
        let open_instances: [OpenInstance<F, CS::Commitment>; IO] =
            open_instances.map(Option::unwrap);

        let instance = MessageGuard::new(open_instances);
        let proof = transcript.receive_message_delayed(|proof| proof.batching_proof.clone());
        let open_instance = MultipointBatching::verify_reduction(
            &key.batching,
            instance,
            transcript.new_guard(proof),
        )?;

        let instance = MessageGuard::new(open_instance);
        let proof = transcript.receive_message_delayed(|proof| proof.open_proof.clone());

        CS::verify(&key.pcs, instance, transcript.new_guard(proof)).map_err(Error::Pcs)?;

        Ok(())
    }

    fn prove(_instance: Self::Instance) -> Self::Proof {
        todo!()
    }
}
