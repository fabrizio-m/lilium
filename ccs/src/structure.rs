use crate::constraint_system::{
    cs_prototype::{GateRegistry, Zero},
    ConstraintSystem, Gate, Var,
};
use ark_ff::Field;
use std::collections::HashMap;

///with key being the variable and the value the number of times it appears (or its exponent)
pub struct MultiSet(HashMap<usize, usize>);
///sparse matrix
#[derive(Default, Clone)]
pub struct Matrix {
    ///assumes each non zero value to be one, should be enough to represent plonk
    /// considering that most rows will likely have a single 1 the vector represation may be suboptimal
    rows: Vec<Vec<usize>>,
    //generalized version that supports arbitrary values
    //rows: Vec<Vec<(usize, F)>>,
}

impl Matrix {
    fn with_capacity(capacity: usize) -> Self {
        Matrix {
            rows: Vec::with_capacity(capacity),
        }
    }
    fn push_row_single_value(&mut self, idx: usize) {
        self.rows.push(vec![idx])
    }
}
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
pub struct CcsStructure<const IO: usize, const S: usize, F: Field> {
    io_matrices: [Matrix; IO],
    selector_matrices: [SelectorMatrix; S],
    input_len: usize,
    ///with each multiset representing a term, and with corresponding constant coefficient
    multisets: Vec<(F, MultiSet)>,
}

#[derive(Debug)]
struct Constraint<T, const IO: usize> {
    ///it probably better to just fill unused space with zeros than to have a bunch of [Vec]s
    io: [T; IO],
    len: usize,
    selector: usize,
}
pub struct StructureBuilder<const IO: usize> {
    next: usize,
    vars: Vec<usize>,
    //hashmap may not be the best
    registry: GateRegistry,
    constraints: Vec<Constraint<usize, IO>>,
}
impl Var for usize {}

impl<const MAX_IO: usize> StructureBuilder<MAX_IO> {
    pub fn new() -> Self {
        let registry = GateRegistry::new();
        // registry.register_gate::<Add>();
        Self {
            next: 0,
            vars: vec![],
            registry,
            constraints: vec![],
        }
    }
    fn var(&mut self) -> usize {
        //in this way 0 is reserved for the 1
        self.next += 1;
        let v = self.next;
        self.vars.push(v);
        v
    }
    /// allows `f` to access the internal [GateRegistry]
    pub(crate) fn register_gates<F: FnOnce(&mut GateRegistry)>(&mut self, f: F) {
        let registry = &mut self.registry;
        f(registry);
    }
    pub fn with_inputs<const I: usize>() -> (Self, [usize; I]) {
        let mut new = Self::new();
        let inputs = [(); I].map(|_| new.var());
        (new, inputs)
    }
    pub fn link_outputs<const I: usize, const O: usize>(&mut self, outputs: [usize; O]) {
        for i in 0..O {
            let a = i + I + 1;
            let b = outputs[i];
            Self::execute::<Zero, 2, 2, 0>(self, [a, b]);
        }
    }
    fn bit_decomposition<const BITS: usize>(mut selector: usize) -> [bool; BITS] {
        let mut bits = [false; BITS];
        for i in 0..BITS {
            bits[i] = selector & 1 == 1;
            selector = selector >> 1;
        }
        bits
    }
    pub fn build<F: Field, const S: usize>(
        self,
        public_io_len: usize,
    ) -> CcsStructure<MAX_IO, S, F> {
        let Self {
            registry,
            constraints,
            ..
        } = self;

        let mut io_matrices = [(); MAX_IO].map(|_| Matrix::with_capacity(constraints.len()));
        let mut selector_matrices =
            [(); S].map(|_| SelectorMatrix::with_capacity(constraints.len()));

        for constraint in constraints.into_iter() {
            let constraint: Constraint<usize, MAX_IO> = constraint;
            let Constraint { io, len, selector } = constraint;
            for i in 0..len {
                io_matrices[i].push_row_single_value(io[0]);
            }
            let selector = Self::bit_decomposition::<S>(selector);
            for i in 0..S {
                selector_matrices[i].rows.push(selector[i]);
            }
        }
        ///todo
        let multisets = vec![];
        CcsStructure {
            input_len: public_io_len,
            io_matrices,
            selector_matrices,
            multisets,
        }
    }
}
impl<const MAX_IO: usize> ConstraintSystem for StructureBuilder<MAX_IO> {
    ///TODO;
    const S: usize = 5;

    type V = usize;

    fn make_gates() -> Vec<u8> {
        todo!()
    }

    fn execute<G, const IO: usize, const I: usize, const O: usize>(
        &mut self,
        inputs: [Self::V; I],
    ) -> [Self::V; O]
    where
        G: Gate<IO, I, O> + 'static,
    {
        let mut io = [0; MAX_IO];
        for i in 0..I {
            io[i] = inputs[i];
        }
        let selector = self.registry.selector::<G>();
        let output = [(); O].map(|_| self.var());
        for i in 0..O {
            io[i + I] = output[i];
        }
        let constraint = Constraint {
            io,
            len: IO,
            selector,
        };
        self.constraints.push(constraint);
        output
    }
}
