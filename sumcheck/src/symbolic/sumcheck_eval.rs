use crate::{
    degree::DegreeEnv,
    polynomials::Evals,
    sumcheck::SumcheckFunction,
    symbolic::{
        compute::MvPoly,
        evaluate::{MvEvaluator, MvIr},
        expression::{compute_mv_poly, ExpEnv, Expression, VarOrChall},
        message_eval::MessageEvaluator,
    },
};
use ark_ff::Field;
use std::{collections::BTreeMap, iter::successors};

pub struct SumcheckEvaluator<F: Field, S>
where
    S: SumcheckFunction<F>,
{
    inner: MessageEvaluator<F, u8>,
    var_map: Vec<S::Idx>,
    message_len: usize,
    /// initial stack value for accumulator, 0s.
    accumulator_init: Vec<F>,
}

type Var<F, S> = VarOrChall<<S as SumcheckFunction<F>>::Idx, <S as SumcheckFunction<F>>::ChallIdx>;

impl<F: Field, S> SumcheckEvaluator<F, S>
where
    S: SumcheckFunction<F>,
{
    pub fn new() -> Self {
        let env = ExpEnv;
        ///TODO: challenges are being treated as constants, which will result in them
        ///becoming coefficients, fix that.
        // Build expression tree.
        let exp: Expression<F, S::Idx, S::ChallIdx> = S::function(env);
        // Evaluate tree into MV polynomial.
        let poly: MvPoly<F, Var<F, S>> = compute_mv_poly(exp);
        // Simplify into abstract stack machine operations.
        let evaluator = MvEvaluator::new(poly);
        let program: &[MvIr<F, Var<F, S>>] = evaluator.program();
        // Modify program, translating indices to u8.
        let (ir, var_map) = Self::transpile(program);
        let message_len = Self::message_len();
        // Create message evaluator, main stack machine with a concrete and
        // optimized instruction set.
        let inner: MessageEvaluator<F, u8> = MessageEvaluator::new(ir, message_len);
        let accumulator_init = vec![F::zero(); message_len];

        Self {
            inner,
            var_map,
            message_len,
            accumulator_init,
        }
    }

    /// Translates indices from `Var<F,S>` into `u8`, and creates a map to resolve
    /// `u8` -> `Var<F,S>`.
    /// Also adds an extra `MvIr::Add` instruction at the end to accumulate the result
    /// into some previous result present at the start of the stack.
    fn transpile(program: &[MvIr<F, Var<F, S>>]) -> (Vec<MvIr<F, u8>>, Vec<S::Idx>) {
        // Using KINDS as a way of getting a default value.
        let kinds = S::KINDS;
        // assign a temporal integer id to each eval;
        let ids = S::map_evals(kinds, |_| ());
        let ids = ids.flatten_vec().into_iter().enumerate().map(|(id, _)| id);
        let ids: S::Mles<usize> = S::Mles::unflatten_vec(ids.collect());

        // To later resolve integer ids to S::Idx.
        let mut lookup: BTreeMap<usize, S::Idx> = BTreeMap::new();

        // For the true ids, done this way so that indices are provided
        // in the same order in which they are read in the program.
        let mut next_id = successors(Some(0u8), |x| x.checked_add(1));
        let mut true_ids: BTreeMap<usize, u8> = BTreeMap::new();
        let ir = program.iter().map(|instruction| {
            let instruction: &MvIr<F, Var<F, S>> = instruction;
            let mut map_var = |var: S::Idx| {
                let temp_id = *ids.index(var);
                // Overwriting as (k,v) should be the same.
                let _ = lookup.insert(temp_id, var);
                let id = true_ids
                    .entry(temp_id)
                    .or_insert_with(|| next_id.next().unwrap());
                *id
            };
            let mut map_var = |var: Var<F, S>| match var {
                VarOrChall::Var(var) => map_var(var),
                VarOrChall::Challenge(chall) => {
                    //TODO: have to handle challenges
                    todo!()
                }
            };
            match instruction {
                MvIr::PushChild(coeff, var) => MvIr::PushChild(*coeff, map_var(*var)),
                MvIr::Add => MvIr::Add,
                MvIr::Mul(var) => MvIr::Mul(map_var(*var)),
            }
        });
        // adding an extra Add at the end to accumulate results.
        let ir: Vec<MvIr<F, u8>> = ir.chain([MvIr::Add]).collect();
        // Invert and merge mapping into u8 -> S::Idx.
        let lookup: BTreeMap<u8, S::Idx> = true_ids
            .into_iter()
            .map(|(temp_id, true_id)| {
                let var: S::Idx = *lookup.get(&temp_id).unwrap();
                (true_id, var)
            })
            .collect();
        // Turn it into a Vec with the u8 index implicit.
        let lookup_len: u8 = lookup.len().try_into().unwrap();
        let lookup: Vec<S::Idx> = (0_u8..lookup_len)
            .map(|i| *lookup.get(&i).unwrap())
            .collect();
        (ir, lookup)
    }
    fn message_len() -> usize {
        let env = DegreeEnv::new();
        let degree = S::function(env);
        // as a degree d polynomial requires d + 1 evaluations.
        degree.0 + 1
    }
    fn eval_accumulate(&mut self, evals: [&S::Mles<F>; 2]) {
        let [left, right] = evals;
        assert_eq!(self.inner.result().len(), self.message_len);
        for i in 0..self.var_map.len() {
            let index: S::Idx = self.var_map[i];
            let left = left.index(index);
            let right = right.index(index);
            self.inner.set_var(i, (*left, *right));
        }
        self.inner.eval();
    }
    /// Creates accumulator.
    pub fn accumulator(&mut self) -> EvalAccumulator<F, S> {
        self.inner.set_stack(&self.accumulator_init);
        EvalAccumulator(self)
    }
}

/// Wrapper over `SumcheckEvaluator` that accumulates multiple evaluations
/// through addition, and can be consumed to get the accumulated result.
pub struct EvalAccumulator<'a, F: Field, S>(&'a mut SumcheckEvaluator<F, S>)
where
    S: SumcheckFunction<F>;

impl<'a, F: Field, S> EvalAccumulator<'a, F, S>
where
    S: SumcheckFunction<F>,
{
    /// Evaluates function with provided evals, adding result into
    /// internal accumulator.
    pub fn eval_accumulate(&mut self, evals: [&S::Mles<F>; 2]) {
        self.0.eval_accumulate(evals);
    }
    /// Consumes itself, releasing accumulated result and the inner &mut.
    pub fn finish(self) -> Vec<F> {
        let message_len = self.0.message_len;
        let stack_len = self.0.inner.result().len();
        assert_eq!(message_len, stack_len);
        let res = self.0.inner.result().to_vec();
        // Cleaning stack, not strictly necessary, as it will
        // be initialized on use.
        self.0.inner.set_stack(&[]);
        res
    }
}
