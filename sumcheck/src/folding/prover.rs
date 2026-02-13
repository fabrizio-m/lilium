use crate::{
    folding::{SumFold, SumFoldInstance, SumFoldProof},
    message::Message,
    polynomials::Evals,
    sumcheck::{Sum, SumcheckFunction},
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use transcript::Transcript;

pub struct SumFoldProverOutput<F: Field, SF: SumcheckFunction<F>> {
    pub instance: SumFoldInstance<F, 2>,
    pub folded_witness: Vec<SF::Mles<F>>,
    pub proof: SumFoldProof<F>,
}

impl<F: Field, SF: SumcheckFunction<F>> SumFold<F, SF> {
    pub fn fold<S: Duplex<F>>(
        &self,
        mut w1: Vec<SF::Mles<F>>,
        w2: &[SF::Mles<F>],
        sums: Option<SumFoldInstance<F, 2>>,
        transcript: &mut Transcript<F, S>,
        sumcheck_challs: SF::Challs,
    ) -> SumFoldProverOutput<F, SF> {
        let mut evaluator = self.evaluator.clone();
        let accumulator = evaluator.accumulator(&sumcheck_challs);

        let message = w1
            .iter()
            .zip(w2.iter())
            .fold(accumulator, |mut acc, evals| {
                let (e1, e2) = evals;
                acc.eval_accumulate([e1, e2]);
                acc
            })
            .finish();
        let message = Message::new(message);

        let instance = if let Some(sums) = sums {
            assert_eq!(sums.sums[0].0, message.eval_at_0());
            assert_eq!(sums.sums[1].0, message.eval_at_1());
            sums
        } else {
            SumFoldInstance {
                sums: [message.eval_at_0(), message.eval_at_1()].map(Sum),
            }
        };

        let [beta] = transcript.send_message(&instance).unwrap();

        // let eq_beta = Message::new(vec![F::one() - beta, beta]);
        let eq_beta = Message::new_degree_n(F::one() - beta, beta, self.degree + 1);
        let message = {
            let extended = message.clone().extend(&self.weights);
            extended * eq_beta
        };
        let [r] = transcript.send_message(&message).unwrap();

        {
            let sum = instance.sums[0].0 * (F::ONE - beta) + instance.sums[1].0 * beta;
            let eval_zero = message.eval_at_0();
            let eval_one = message.eval_at_1();
            assert_eq!(sum, eval_zero + eval_one);
        }

        let proof = SumFoldProof { message };

        for (e1, e2) in w1.iter_mut().zip(w2.iter()) {
            let folded = e1.combine(e2, |e1, e2| e1 * (F::ONE - r) + e2 * r);
            *e1 = folded;
        }
        let folded_witness = w1;

        SumFoldProverOutput {
            instance,
            folded_witness,
            proof,
        }
    }
}
