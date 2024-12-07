use crate::multivariate::compute::{MvPoly, MvPolyTerm};
use ark_ff::Field;
use std::{collections::BTreeMap, iter::Iterator};

/// A representation of a multivariate polynomial optimized for evaluation,
/// as such it doesn't support any operation
#[derive(Debug, Clone)]
pub struct MvEvaluator<F: Field, V> {
    pub operations: Vec<Op<V>>,
    pub operands: Vec<(F, V)>,
}

/// Whether to take from operands or from the stack of partial results
#[derive(Debug, Clone)]
pub enum OperandOrStack {
    Operand,
    Stack,
}
#[derive(Debug, Clone)]
pub enum Op<V> {
    /// Pop 1 from stack and 1 from either stack or operands, add and push
    /// into stack
    Add(OperandOrStack),
    /// Pop from stack, multiply by V and push back
    Mul(V),
    /// Pop from operands, push to stack
    OperandToStack,
}

enum EvalTree<F: Field, V> {
    Parent(V, Vec<Self>),
    Child(V, F),
}

type Term<F, V> = (MvPolyTerm<V>, F);

impl<F: Field, V> MvEvaluator<F, V>
where
    V: Eq + Ord + Clone,
{
    pub fn new(poly: MvPoly<F, V>) -> MvEvaluator<F, V> {
        let top_level_nodes = Self::build_nodes(poly.terms);
        // take some random var
        let dummy_var = match &top_level_nodes[0] {
            EvalTree::Parent(var, _) | EvalTree::Child(var, _) => var.clone(),
        };
        // adding a fake var to group all into a single tree, this var will later be discarded
        let root = EvalTree::Parent(dummy_var, top_level_nodes);

        let mut operations = vec![];
        let mut operands = vec![];
        Self::tree_operations(&mut operations, &mut operands, root);
        match operations.pop().unwrap() {
            Op::Mul(_) => {}
            _ => panic!("last operation should be Mul"),
        }
        Self {
            operations,
            operands,
        }
    }
    /// Flattens the tree into operations and operands
    fn tree_operations(
        operations: &mut Vec<Op<V>>,
        operands: &mut Vec<(F, V)>,
        tree: EvalTree<F, V>,
    ) -> OperandOrStack {
        match tree {
            EvalTree::Parent(var, children) => {
                let mut locations = Vec::with_capacity(children.len());
                for child in children.into_iter().rev() {
                    let location = Self::tree_operations(operations, operands, child);
                    locations.push(location);
                }
                let mut locations = locations.into_iter();
                let first = locations.next().unwrap();
                if let OperandOrStack::Operand = first {
                    operations.push(Op::OperandToStack);
                }
                for location in locations {
                    operations.push(Op::Add(location));
                }
                operations.push(Op::Mul(var));
                OperandOrStack::Stack
            }
            EvalTree::Child(var, coeff) => {
                operands.push((coeff, var));
                OperandOrStack::Operand
            }
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
}
