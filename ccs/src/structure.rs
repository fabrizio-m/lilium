pub use crate::matrix::Matrix;
use crate::{
    circuit::Var,
    constraint_system::{cs_prototype::GateRegistry, ConstraintSystem, Constraints, Gate, Val},
    gates::Equality,
};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt::Display,
    ops::{Add, Mul, Sub},
};

///with key being the variable and the value the number of times it appears (or its exponent)
#[derive(Clone, Debug)]
pub struct MultiSet<T>(BTreeMap<T, usize>);

impl<T> Default for MultiSet<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

/*
/// considering that each row will either be 0 or 1 just in the first element,
/// it can be represented with just Vec<bool>
#[derive(Default)]
pub struct SelectorMatrix {
    rows: Vec<bool>,
}

impl SelectorMatrix {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            rows: Vec::with_capacity(capacity),
        }
    }
}
*/

#[derive(PartialEq, Eq, Clone)]
pub enum MatrixIndex {
    Io(usize),
    Selector(usize),
}

impl MatrixIndex {
    fn order(&self, b: &Self) -> Ordering {
        use MatrixIndex::{Io, Selector};
        match (self, b) {
            (Io(_), Selector(_)) => Ordering::Less,
            (Selector(_), Io(_)) => Ordering::Greater,
            (Io(a), Io(b)) | (Selector(a), Selector(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for MatrixIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MatrixIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order(other)
    }
}

#[derive(Clone, Debug)]
pub struct CcsStructure<const IO: usize, const S: usize> {
    pub io_matrices: [Matrix; IO],
    /// Where each entry is in 0..S reprensenting the gate to active.
    pub gate_selectors: Vec<usize>,
    pub input_len: usize,
    //with each multiset representing a term, and with corresponding constant coefficient
    pub gates: Vec<Constraints<Exp<usize>>>,
    /// public_io + witness + 1
    pub trace_len: usize,
}

impl<const IO: usize, const S: usize> CcsStructure<IO, S> {
    /// vars needed to fir the trace
    pub fn vars(&self) -> usize {
        let len_padded = self.trace_len.next_power_of_two();
        len_padded.ilog2() as usize
    }
}

#[derive(Debug)]
/// An individual instance of a gate, contains the variables and the id of the gate.
struct Constraint<T, const IO: usize> {
    ///It's probably better to just fill unused space with zeros than to have a bunch of `Vec`s
    io: [T; IO],
    /// Length of `io`.
    len: usize,
    selector: usize,
}

/// Builder creates the structure for a circuit through symbolic variables.
#[derive(Debug, Default)]
pub struct StructureBuilder<const IO: usize> {
    next: usize,
    vars: Vec<usize>,
    registry: GateRegistry,
    constraints: Vec<Constraint<WitnessIndex, IO>>,
}

#[derive(Clone, Copy, Debug)]
/// Variable that points to a position in the witness.
pub struct WitnessIndex(usize);

impl Add for WitnessIndex {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        panic!(
            "tried to add {:?} and {:?}, this type of var should never be added",
            self, rhs
        );
    }
}

impl Sub for WitnessIndex {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        panic!(
            "tried to subtract {:?} and {:?}, this type of var should never be subtracted",
            self, rhs
        );
    }
}

impl Mul for WitnessIndex {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        panic!(
            "tried to multiply {:?} and {:?}, this type of var should never be multiplied",
            self, rhs
        );
    }
}

impl Val for WitnessIndex {}

impl<const MAX_IO: usize> StructureBuilder<MAX_IO> {
    pub fn gate_counts(&self) -> Vec<(&'static str, usize)> {
        let registry = &self.registry;
        let constraints = &self.constraints;
        let mut counts = vec![0; registry.gate_registry.len()];

        for constraint in constraints {
            counts[constraint.selector] += 1;
        }

        let mut named_counts = counts.into_iter().map(|c| ("", c)).collect::<Vec<_>>();

        for gate in registry.gate_registry.values() {
            named_counts[gate.0].0 = gate.2;
        }

        named_counts
    }

    fn var(&mut self) -> WitnessIndex {
        //in this way 0 is reserved for the 1
        self.next += 1;
        let v = self.next;
        self.vars.push(v);
        WitnessIndex(v)
    }
    pub fn with_inputs<const I: usize>() -> (Self, [WitnessIndex; I]) {
        let mut new = Self::default();
        let inputs = [(); I].map(|_| new.var());
        (new, inputs)
    }
    /// reserve space for the public output
    pub fn reserve_outputs<const O: usize>(&mut self) {
        for _ in 0..O {
            let _ = self.var();
        }
    }
    pub fn link_outputs<const I: usize, const O: usize>(&mut self, outputs: [WitnessIndex; O]) {
        for (i, b) in outputs.into_iter().enumerate() {
            let a = WitnessIndex(i + I + 1);
            Self::execute::<Equality, 2, 2, 0>(self, [a, b].map(Var));
        }
    }
    /*fn bit_decomposition<const BITS: usize>(mut selector: usize) -> [bool; BITS] {
        let mut bits = [false; BITS];
        for i in 0..BITS {
            bits[i] = selector & 1 == 1;
            selector = selector >> 1;
        }
        bits
    }*/
    pub fn build<const S: usize>(self, public_io_len: usize) -> CcsStructure<MAX_IO, S> {
        let Self {
            registry,
            constraints,
            ..
        } = self;

        let mut io_matrices = [(); MAX_IO].map(|_| Matrix::with_capacity(constraints.len()));
        let mut gate_selectors = vec![];

        for constraint in constraints.into_iter() {
            let constraint: Constraint<WitnessIndex, MAX_IO> = constraint;
            let Constraint { io, len, selector } = constraint;
            for i in 0..len {
                io_matrices[i].push_row_single_value(io[i].0);
            }
            (len..MAX_IO).for_each(|i| {
                io_matrices[i].push_row_empty();
            });
            gate_selectors.push(selector);
            // let selector = Self::bit_decomposition::<S>(selector);

            //TODO: for now using simpler linear selectors

            if selector >= S {
                panic!("not enough selectors for all gates, increase S");
            }
        }

        let gates = registry.expressions_sorted();

        let trace_len = self.vars.len();
        assert_eq!(trace_len, self.next);
        CcsStructure {
            input_len: public_io_len,
            io_matrices,
            gate_selectors,
            gates,
            trace_len,
        }
    }
}

impl<const MAX_IO: usize> ConstraintSystem<WitnessIndex> for StructureBuilder<MAX_IO> {
    fn execute<G, const IO: usize, const I: usize, const O: usize>(
        &mut self,
        inputs: [Var<WitnessIndex>; I],
    ) -> [Var<WitnessIndex>; O]
    where
        G: Gate<IO, I, O> + 'static,
    {
        let inputs = inputs.map(Var::unwrap);
        let mut io = [WitnessIndex(0); MAX_IO];
        io[..I].copy_from_slice(&inputs[..I]);

        let output = [(); O].map(|_| self.var());
        io[I..(I + O)].copy_from_slice(&output[..O]);

        let selector = self.registry.selector::<G, IO, I, O>();

        let constraint = Constraint {
            io,
            len: IO,
            selector,
        };
        self.constraints.push(constraint);
        output.map(Var)
    }
}

#[derive(Debug, Clone)]
pub enum Exp<T> {
    Atom(T),
    Add(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
}

impl<T> Add<Self> for Exp<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::Add(Box::new(self), Box::new(rhs))
    }
}

impl<T> Mul<Self> for Exp<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::Mul(Box::new(self), Box::new(rhs))
    }
}

impl<T> Sub<Self> for Exp<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Sub(Box::new(self), Box::new(rhs))
    }
}

impl<T: Clone> Val for Exp<T> {}

impl<T: Display> Display for MultiSet<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, n) in self.0.iter() {
            for _ in 0..*n {
                write!(f, "v{i}")?;
            }
        }
        writeln!(f)
    }
}

/*impl<T: Ord> Mul<Self> for MultiSet<T> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        for (i, n) in rhs.0.into_iter() {
            *self.0.entry(i).or_insert(0) += n;
        }
        self
    }
}*/

impl<T: Ord + Clone> Exp<T> {
    pub fn map<V, F>(self, f: &F) -> Exp<V>
    where
        F: Fn(T) -> V,
    {
        use Exp::*;
        match self {
            Atom(v) => Atom(f(v)),
            Add(e1, e2) => Add(Box::new(e1.map(f)), Box::new(e2.map(f))),
            Mul(e1, e2) => Mul(Box::new(e1.map(f)), Box::new(e2.map(f))),
            Sub(e1, e2) => Sub(Box::new(e1.map(f)), Box::new(e2.map(f))),
        }
    }
}

/*#[test]
fn exp_to_multiset() {
    use ark_vesta::Fr;
    let a = Exp::Atom(0);
    let b = Exp::Atom(1);
    let c = Exp::Atom(2);
    let s1 = Exp::Atom(3);
    let s2 = Exp::Atom(4);
    let add = (a.clone() + b.clone() - c.clone()) * s1;
    let mul = (a * b - c) * s2;
    let exp = add + mul;
    println!("exp:\n{:#?}", exp);
    let multisets = exp.to_multisets::<Fr>();
    // println!("multisets:\n{}", multisets);
    for multiset in multisets {
        println!("{} * {} +", multiset.0, multiset.1);
    }
}*/

impl GateRegistry {
    fn expressions_sorted(self) -> Vec<Constraints<Exp<usize>>> {
        let mut gates: Vec<(usize, Constraints<Exp<usize>>)> = self
            .gate_registry
            .into_values()
            .map(|(id, c, _)| (id, c))
            .collect();
        gates.sort_by_key(|x| x.0);
        for (i1, (i2, _)) in gates.iter().enumerate() {
            assert_eq!(i1, *i2, "unexpected index");
        }
        gates.into_iter().map(|(_, exp)| exp).collect()
    }
}
