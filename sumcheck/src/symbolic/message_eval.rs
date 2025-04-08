//! Optimized machine to evaluate polynomials over sumcheck messages,
//! which are univariate polynomials.
//! It allocates no additional memory, and has decent cache locality.
//! It does not utilize the abstraction in `automata`, as generalizing
//! them for this unique use case would add too much complexity.

use crate::symbolic::evaluate::MvIr;
use ark_ff::Field;
use std::cmp::Ord;

/// Instruction set optimized for univariate polynomials
/// (in evaluation form) as operands.
enum Instruction<V> {
    Add,
    Mul,
    Load(V),
    Eval,
    EvalWithCoeff,
}

/// Translate instruction set, also extracting coeffcients into a
/// Vec<F>.
fn translate<F, V>(program: Vec<MvIr<F, V>>) -> (Vec<Instruction<V>>, Vec<F>) {
    use Instruction::*;
    let mut instructions = vec![];
    let mut coeffs = vec![];
    for instruction in program {
        match instruction {
            MvIr::PushChild(coeff, var) => {
                coeffs.push(coeff);
                instructions.extend([Load(var), EvalWithCoeff]);
            }
            MvIr::Add => {
                instructions.push(Add);
            }
            MvIr::Mul(var) => {
                instructions.extend([Load(var), Eval, Mul]);
            }
        }
    }
    (instructions, coeffs)
}

/// Splits off, 2 &mut [F] of length message_len from the top of the stack.
fn pop_2<F>(stack: &mut [F], message_len: usize) -> [&mut [F]; 2] {
    let split_at = stack.len() - (message_len * 2);
    let (_, right) = stack.split_at_mut(split_at);
    let (left, right) = right.split_at_mut(message_len);
    [left, right]
}

/// Based on `Message::new_degree_n`, extends the stack with the evals.
fn eval<F: Field>(e0: F, e1: F, stack: &mut Vec<F>, message_len: usize) {
    // P(x) = (e1 - e0)x + e0
    let original_len = stack.len();
    stack.resize(original_len + message_len, e0);
    let (_, evals) = stack.split_at_mut(original_len);

    let diff = e1 - e0;
    let mut last = F::zero();
    for e in evals {
        let e: &mut F = e;
        *e += last;
        last = last + diff;
    }
}

/// Stack machine optimized to operate over univariate polynomials, the
/// sumcheck messages specifically.
pub(crate) struct MessageEvaluator<F, V> {
    program: Vec<Instruction<V>>,
    coefficients: Vec<F>,
    vars: Vec<(F, F)>,
    stack: Vec<F>,
    message_len: usize,
}

/// Could be implemented for a bigger integer than u8.
impl<F: Field> MessageEvaluator<F, u8> {
    pub(crate) fn new(ir: Vec<MvIr<F, u8>>, message_len: usize) -> Self {
        let (program, coefficients) = translate(ir);
        let (bound, vars) = Self::analyze(&program, message_len);
        let vars = vec![(F::zero(), F::zero()); vars as usize + 1];
        let stack = Vec::with_capacity(bound);
        Self {
            program,
            coefficients,
            vars,
            stack,
            message_len,
        }
    }
    /// Returns (stack_bound, highest_var).
    fn analyze(program: &[Instruction<u8>], message_size: usize) -> (usize, u8) {
        use Instruction::*;
        let mut bound = 0;
        let mut stack = 0;
        let mut highest_var = 0;
        for instruction in program {
            let instruction: &Instruction<u8> = instruction;
            stack = match instruction {
                Add | Mul => stack - message_size,
                Load(var) => {
                    highest_var = Ord::max(highest_var, *var);
                    stack + 2
                }
                Eval | EvalWithCoeff => (stack - 2) + message_size,
            };
            bound = Ord::max(bound, stack);
        }
        (bound, highest_var)
    }
    /// Eval leaving the result as the only elements in the stack.
    /// Before call, variables should be set, and stack must be empty.
    pub(crate) fn eval(&mut self) {
        let mut stack = &mut self.stack;
        let mut coeffs = self.coefficients.iter();
        let message_len = self.message_len;
        let memory = &self.vars;

        for instruction in &self.program {
            let instruction: &Instruction<u8> = instruction;
            match instruction {
                Instruction::Add => {
                    let [left, right] = pop_2(&mut stack, message_len);
                    for (a, b) in left.into_iter().zip(right) {
                        *a += b;
                    }
                    stack.truncate(stack.len() - message_len);
                }
                Instruction::Mul => {
                    let [left, right] = pop_2(&mut stack, message_len);
                    for (a, b) in left.into_iter().zip(right) {
                        *a *= b;
                    }
                    stack.truncate(stack.len() - message_len);
                }
                Instruction::Load(var) => {
                    let (e0, e1) = memory[*var as usize];
                    stack.push(e0);
                    stack.push(e1);
                }
                Instruction::Eval => {
                    let e1 = stack.pop().unwrap();
                    let e0 = stack.pop().unwrap();
                    eval(e0, e1, &mut stack, message_len);
                }
                Instruction::EvalWithCoeff => {
                    let coeff: &F = coeffs.next().unwrap();
                    let mut e2 = stack.pop().unwrap();
                    let mut e1 = stack.pop().unwrap();
                    e1 *= coeff;
                    e2 *= coeff;
                }
            }
        }
    }

    /// Returns result left on the stack, panics on unexpected
    /// stack size.
    pub(crate) fn result(&self) -> &[F] {
        assert_eq!(self.stack.len(), self.message_len);
        &self.stack
    }

    /// Truncates stack to length 0, then extends it
    /// with the provided elements.
    pub(crate) fn set_stack(&mut self, new_stack: &[F]) {
        self.stack.truncate(0);
        self.stack.extend(new_stack);
    }

    pub(crate) fn set_var(&mut self, idx: usize, eval: (F, F)) {
        self.vars[idx] = eval;
    }
}
