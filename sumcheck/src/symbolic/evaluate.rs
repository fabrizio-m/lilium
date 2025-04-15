use crate::symbolic::compute::{MvPoly, MvPolyTerm};
use ark_ff::Field;
use automata::memory_machine::Memory;
use std::{collections::BTreeMap, fmt::Debug, iter::Iterator};

/// A representation of a multivariate polynomial optimized for evaluation,
/// as such it doesn't support any operation.
/// Essentiall Horner's rule with memory optimizations
#[derive(Debug, Clone)]
pub struct MvEvaluator<F: Field, V> {
    program: Vec<MvIr<F, V>>,
}

// TODO: Explore using Pippenger instead.

/// Stack machine instructions to evaluate a multivariate polynomial.
/// Can be used together with a V -> F map to resolve variables, and
/// a stack to evaluate the polynomial.
/// It aims first to be simple and abstract, it can be used directly
/// or as an IR to create a more performant instructions.
#[derive(Debug, Clone)]
pub enum MvIr<F, V> {
    // (coeff,var), push 1.
    PushChild(F, V),
    // pop 2, push 1
    Add,
    // pop 1, push 1
    Mul(V),
    // pop 1, push 1
    AddConstantTerm(F),
}

#[derive(Clone, Debug)]
enum EvalTree<F: Field, V> {
    Parent(V, Vec<Self>),
    Child(V, F),
}

type Term<F, V> = (MvPolyTerm<V>, F);

impl<F: Field, V> MvEvaluator<F, V>
where
    V: Eq + Ord + Clone + Debug,
{
    pub fn new(poly: MvPoly<F, V>) -> MvEvaluator<F, V> {
        let (poly, constant_term) = poly.extract_constant_term();
        let top_level_nodes = Self::build_nodes(poly.terms);
        // take some random var
        let dummy_var = match &top_level_nodes[0] {
            EvalTree::Parent(var, _) | EvalTree::Child(var, _) => var.clone(),
        };
        // adding a fake var to group all into a single tree, this var will later be discarded
        let root = EvalTree::Parent(dummy_var, top_level_nodes);

        let mut program = vec![];
        Self::tree_operations(&mut program, root);
        match program.pop().unwrap() {
            MvIr::Mul(_) => {}
            _ => panic!("last operation should be Mul"),
        }
        if let Some(coeff) = constant_term {
            program.push(MvIr::AddConstantTerm(coeff));
        }
        Self { program }
    }

    fn tree_operations(operations: &mut Vec<MvIr<F, V>>, tree: EvalTree<F, V>) {
        match tree {
            EvalTree::Parent(var, children) => {
                let mut nodes = 0;
                for child in children.into_iter() {
                    Self::tree_operations(operations, child);
                    nodes += 1;
                }
                let adds = nodes - 1;
                for _ in 0..adds {
                    operations.push(MvIr::Add);
                }
                operations.push(MvIr::Mul(var));
            }
            EvalTree::Child(var, coeff) => operations.push(MvIr::PushChild(coeff, var)),
        }
    }
    /// Turn terms into trees
    fn build_nodes(terms: Vec<Term<F, V>>) -> Vec<EvalTree<F, V>> {
        let (degree_1, rest): (_, Vec<Term<F, V>>) =
            terms.to_vec().into_iter().partition(|t| t.0.degree() == 1);
        let mut nodes: Vec<EvalTree<F, V>> = degree_1
            .into_iter()
            .map(|x: Term<F, V>| {
                let (var, coeff) = x;
                let var = var.unwrap_single_var();
                EvalTree::Child(var, coeff)
            })
            .collect();
        let partitions = Self::partition(rest);
        for (v, terms) in partitions.into_iter() {
            let children = Self::build_nodes(terms);
            let node = EvalTree::Parent(v, children);
            nodes.push(node);
        }
        nodes
    }
    /// Group terms by common variables and extract them
    fn partition(terms: Vec<Term<F, V>>) -> Vec<(V, Vec<Term<F, V>>)> {
        if terms.is_empty() {
            vec![]
        } else {
            let (v, [partition, rest]) = Self::partition_by_var(terms);
            let partition = (v, partition);
            let mut partitions = Self::partition(rest);
            partitions.push(partition);
            partitions
        }
    }
    /// Extracts a var from the terms how have it, and splits the term between those who had
    /// the variable removed, and those how didn't have it to begin with.
    /// (var, [extracted, rest])
    fn partition_by_var(terms: Vec<Term<F, V>>) -> (V, [Vec<Term<F, V>>; 2]) {
        let counts = Self::count_vars(&terms);
        let (most_present_var, _) = counts
            .into_iter()
            .max_by_key(|t| t.1)
            .expect("shouldn't be called with empty list");
        let (mut grouped, rest) = terms
            .into_iter()
            .partition::<Vec<Term<F, V>>, _>(|t: &Term<F, V>| t.0.has_var(&most_present_var));
        for term in grouped.iter_mut() {
            term.0.remove_var(&most_present_var);
        }
        (most_present_var, [grouped, rest])
    }
    /// counts on how many terms each variable is present, only 0 or 1 per term,
    /// regardless of power
    fn count_vars(terms: &[Term<F, V>]) -> BTreeMap<V, usize> {
        let mut var_count = BTreeMap::new();
        for term in terms {
            for (var, _) in &term.0.vars {
                let var: V = var.clone();
                let var_count = var_count.entry(var).or_insert(0);
                *var_count += 1;
            }
        }
        var_count
    }
    /// Evaluate with a memory resolving variable to their value.
    pub fn eval<M: Memory<V, F>>(&self, vars: &M) -> F
    where
        V: Copy,
    {
        let program = &self.program;
        let mut stack: Vec<F> = vec![];
        for instruction in program.iter() {
            let instruction: &MvIr<F, V> = instruction;
            match instruction {
                MvIr::PushChild(coeff, var) => {
                    let var = vars.read(*var);
                    stack.push(var * coeff);
                }
                MvIr::Add => {
                    let a = stack.pop().unwrap();
                    let b = stack.pop().unwrap();
                    stack.push(a + b);
                }
                MvIr::Mul(var) => {
                    let a = stack.pop().unwrap();
                    let b = vars.read(*var);
                    stack.push(a * b);
                }
                MvIr::AddConstantTerm(coeff) => {
                    let a = stack.pop().unwrap();
                    let b = coeff;
                    stack.push(a + b);
                }
            }
        }
        assert_eq!(stack.len(), 1);
        stack.pop().unwrap()
    }

    /// Provide access to inner program.
    pub fn program(&self) -> &[MvIr<F, V>] {
        &self.program
    }
}
