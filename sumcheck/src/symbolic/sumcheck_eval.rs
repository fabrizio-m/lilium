use crate::{
    degree::DegreeEnv,
    polynomials::Evals,
    sumcheck::SumcheckFunction,
    symbolic::{
        compute::MvPoly,
        evaluate::{MvEvaluator, MvIr},
        expression::{compute_mv_poly, ExpEnv, Expression, VarOrChall},
        id_map::IdMap,
        message_eval::MessageEvaluator,
    },
};
use ark_ff::Field;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct SumcheckEvaluator<F: Field, S>
where
    S: SumcheckFunction<F>,
{
    inner: MessageEvaluator<F, u8>,
    var_map: Vec<S::Idx>,
    chall_map: Vec<S::ChallIdx>,
    message_len: usize,
    /// initial stack value for accumulator, 0s.
    accumulator_init: Vec<F>,
}

impl<F: Field + Clone, S> Clone for SumcheckEvaluator<F, S>
where
    S: SumcheckFunction<F>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            var_map: self.var_map.clone(),
            chall_map: self.chall_map.clone(),
            message_len: self.message_len,
            accumulator_init: self.accumulator_init.clone(),
        }
    }
}

type Var<F, S> = VarOrChall<<S as SumcheckFunction<F>>::Idx, <S as SumcheckFunction<F>>::ChallIdx>;

impl<F: Field, S> Default for SumcheckEvaluator<F, S>
where
    S: SumcheckFunction<F>,
{
    fn default() -> Self {
        Self::new(None)
    }
}

impl<F: Field, S> SumcheckEvaluator<F, S>
where
    S: SumcheckFunction<F>,
{
    pub fn new(f: Option<&S>) -> Self {
        let env = ExpEnv;
        // Build expression tree.
        let exp: Expression<F, S::Idx, S::ChallIdx> = {
            match f {
                Some(f) => f.symbolic_function(env).unwrap(),
                None => S::function(env),
            }
        };
        // Evaluate tree into MV polynomial.
        let poly: MvPoly<F, Var<F, S>> = compute_mv_poly(exp);
        // Simplify into abstract stack machine operations.
        let evaluator = MvEvaluator::new(poly);
        let program: &[MvIr<F, Var<F, S>>] = evaluator.program();
        // Modify program, translating indices to u8.
        let (ir, var_map, chall_map) = Self::transpile(program);
        let message_len = Self::message_len(f);
        // Create message evaluator, main stack machine with a concrete and
        // optimized instruction set.
        let inner: MessageEvaluator<F, u8> = MessageEvaluator::new(ir, message_len);
        let accumulator_init = vec![F::zero(); message_len];

        Self {
            inner,
            var_map,
            chall_map,
            message_len,
            accumulator_init,
        }
    }

    /// Translates indices from `Var<F,S>` into `u8`, and creates a map to resolve
    /// `u8` -> `Var<F,S>`.
    /// Also adds an extra `MvIr::Add` instruction at the end to accumulate the result
    /// into some previous result present at the start of the stack.
    #[allow(clippy::type_complexity)]
    fn transpile(
        program: &[MvIr<F, Var<F, S>>],
    ) -> (
        Vec<MvIr<F, VarOrChall<u8, u8>>>,
        Vec<S::Idx>,
        Vec<S::ChallIdx>,
    ) {
        // Using KINDS as a way of getting a default value.
        let kinds = S::KINDS;
        // assign a temporal integer id to each eval;
        let ids = S::map_evals(kinds, |_| ());
        let ids = ids.flatten_vec().into_iter().enumerate().map(|(id, _)| id);
        // TODO: Add sanity check ensuring that no id is repeated, as that indicates
        // an error in the implementation of flatten or unflatten.
        let ids = ids.collect();
        let ids: S::Mles<usize> = S::Mles::unflatten_vec(ids);

        // To later resolve integer ids to S::Idx.
        let mut lookup: BTreeMap<usize, S::Idx> = BTreeMap::new();

        // For the true ids, done this way so that indices are provided
        // in the same order in which they are read in the program.
        let mut true_ids = IdMap::new();
        let mut chall_ids = IdMap::new();
        let ir = program.iter().map(|instruction| {
            let instruction: &MvIr<F, Var<F, S>> = instruction;
            let mut map_var = |var: S::Idx| {
                let temp_id = *ids.index(var);
                // Overwriting as (k,v) should be the same.
                let _ = lookup.insert(temp_id, var);
                let id = true_ids.get_id(temp_id);
                let id = u8::try_from(id).unwrap();
                VarOrChall::Var(id)
            };
            let mut map_var = |var: Var<F, S>| match var {
                VarOrChall::Var(var) => map_var(var),
                VarOrChall::Challenge(chall) => {
                    let id = chall_ids.get_id(chall);
                    let id = u8::try_from(id).unwrap();
                    VarOrChall::Challenge(id)
                }
            };
            match instruction {
                MvIr::PushChild(coeff, var) => MvIr::PushChild(*coeff, map_var(*var)),
                MvIr::Add => MvIr::Add,
                MvIr::Mul(var) => MvIr::Mul(map_var(*var)),
                MvIr::AddConstantTerm(coeff) => MvIr::AddConstantTerm(*coeff),
            }
        });
        // adding an extra Add at the end to accumulate results.
        let ir: Vec<MvIr<F, VarOrChall<u8, u8>>> = ir.chain([MvIr::Add]).collect();
        // Invert and merge mapping into u8 -> S::Idx.
        let lookup = true_ids
            .finish()
            .into_iter()
            .map(|temp_id| *lookup.get(&temp_id).unwrap())
            .collect();
        let chall_lookup = chall_ids.finish();
        (ir, lookup, chall_lookup)
    }
    fn message_len(f: Option<&S>) -> usize {
        let env = DegreeEnv::new();
        let degree = {
            match f {
                Some(f) => f.symbolic_function(env).unwrap(),
                None => S::function(env),
            }
        };
        // as a degree d polynomial requires d + 1 evaluations.
        degree.0 + 1
    }
    fn set_challs(&mut self, challs: &S::Challs) {
        for i in 0..self.chall_map.len() {
            let index: S::ChallIdx = self.chall_map[i];
            let chall = challs[index];
            self.inner.set_chall(i, chall);
        }
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
    pub fn accumulator(&mut self, challenges: &S::Challs) -> EvalAccumulator<F, S> {
        self.inner.set_stack(&self.accumulator_init);
        self.set_challs(challenges);
        EvalAccumulator(self)
    }
}

/// Wrapper over `SumcheckEvaluator` that accumulates multiple evaluations
/// through addition, and can be consumed to get the accumulated result.
pub struct EvalAccumulator<'a, F: Field, S>(&'a mut SumcheckEvaluator<F, S>)
where
    S: SumcheckFunction<F>;

impl<F: Field, S> EvalAccumulator<'_, F, S>
where
    S: SumcheckFunction<F>,
{
    /// Evaluates function with provided evals, adding result into
    /// internal accumulator.
    pub fn eval_accumulate(&mut self, evals: [&S::Mles<F>; 2]) {
        self.0.eval_accumulate(evals);
    }

    /// Evaluates function with provided evals, adding result into
    /// internal accumulator.
    /// Then the accumulated result is returned and the accumulator
    /// set to zero.
    pub fn eval_and_zero(&mut self, evals: [&S::Mles<F>; 2]) -> Vec<F> {
        self.0.eval_accumulate(evals);
        let message_len = self.0.message_len;
        let stack_len = self.0.inner.result().len();
        assert_eq!(message_len, stack_len);
        let res = self.0.inner.result().to_vec();
        self.0.inner.set_stack(&self.0.accumulator_init);
        res
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
