use std::{marker::PhantomData, ops};

pub trait ConstraintSystem {
    //number of input/outputs available to each gate
    // const IO: usize;
    ///number of selectors, log of the number of gates
    const S: usize;
    type V: Var;

    fn make_gates() -> Vec<u8>;

    fn execute<G, const IO: usize, const I: usize, const O: usize>(
        &mut self,
        i: [Self::V; I],
    ) -> [Self::V; O]
    where
        G: Gate<IO, I, O> + 'static;
}

pub trait Var:
    ops::Add<Output = Self> + ops::Mul<Output = Self> + ops::Sub<Output = Self> + Clone + Copy + Sized
{
}
pub trait Gate<const IO: usize, const I: usize, const O: usize>: Sized + 'static {
    //type Inputs: InputTrait + HasInputs<I>;
    //type Outputs: OutputTrait + HasOutputs<O> + AtLeast<IO>;

    ///computes outputs from inputs
    fn gate<V: Var>(i: [V; I]) -> [V; O];
    ///the output should be zero when the constraint is satisfied
    fn check<V: Var>(i: [V; I], o: [V; O]) -> V;
    /*fn run< CS: ConstraintSystem + Supports2<Self> + EnoughIO<IO>>(
        cs: &mut CS,
        i: [u8; I],
    ) -> [u8; O] {
        cs.execute::<Self, IO, I, O>(i)
    }*/
}

pub struct UseConsts<T, const IO: usize, const I: usize, const O: usize>(PhantomData<T>);

impl<T, const IO: usize, const I: usize, const O: usize> UseConsts<T, IO, I, O> where
    T: Gate<IO, I, O>
{
}

pub mod cs_prototype {
    use std::{
        any::{Any, TypeId},
        collections::HashMap,
    };

    use super::*;

    #[derive(Debug)]
    pub struct GateRegistry {
        //hashmap may not be the best
        gate_registry: HashMap<TypeId, usize>,
        next_selector: usize,
    }

    impl GateRegistry {
        pub fn new() -> Self {
            GateRegistry {
                gate_registry: HashMap::new(),
                //may reserve 0 for equality
                next_selector: 0,
            }
        }
        /// registers [T] to be able to use it, idempotent
        pub fn register_gate<T: Any>(&mut self) {
            let id = TypeId::of::<T>();
            if self.gate_registry.contains_key(&id) {
                panic!("already registered")
            } else {
                //this will reserve 0 for equality
                self.next_selector += 1;
                self.gate_registry.insert(id, self.next_selector);
            }
        }
        pub fn selector<T: Any>(&self) -> usize {
            let id = TypeId::of::<T>();
            *self
                .gate_registry
                .get(&id)
                .expect("use of unregistered gate")
        }
    }

    #[derive(Debug)]
    struct Constraint<T, const IO: usize> {
        io: [T; IO],
        len: usize,
        selector: usize,
    }
    #[derive(Debug)]
    struct ExperimentalConstraintSystem<const IO: usize> {
        next: u8,
        vars: Vec<u8>,
        registry: GateRegistry,
        constraints: Vec<Constraint<u8, IO>>,
    }
    impl<const MAX_IO: usize> ExperimentalConstraintSystem<MAX_IO> {
        fn new() -> Self {
            let mut registry = GateRegistry::new();
            registry.register_gate::<Add>();
            Self {
                next: 0,
                vars: vec![],
                registry,
                constraints: vec![],
            }
        }
        fn var(&mut self) -> u8 {
            let v = self.next;
            self.vars.push(v);
            self.next += 1;
            v
        }
    }
    impl Var for u8 {}
    impl<const MAX_IO: usize> ConstraintSystem for ExperimentalConstraintSystem<MAX_IO> {
        const S: usize = 8;
        type V = u8;

        fn make_gates() -> Vec<u8> {
            vec![]
        }

        fn execute<G, const IO: usize, const I: usize, const O: usize>(
            &mut self,
            inputs: [u8; I],
        ) -> [u8; O]
        where
            G: Gate<IO, I, O> + 'static,
        {
            //for structure creation it isn't necessary to use the inputs or call the gate()
            //just allocate the new variable
            //G::gate(i)
            let mut io = [0_u8; MAX_IO];
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

    pub struct Add;
    impl Gate<3, 2, 1> for Add {
        fn gate<V: Var>([a, b]: [V; 2]) -> [V; 1] {
            //let c = a + b;
            [a + b]
        }

        fn check<V: Var>(i: [V; 2], o: [V; 1]) -> V {
            let ([a, b], [c]) = (i, o);
            a + b - c
        }
    }
    struct Add2;
    impl Gate<3, 2, 1> for Add2 {
        fn gate<V: Var>([a, b]: [V; 2]) -> [V; 1] {
            [a + b]
        }

        fn check<V: Var>(i: [V; 2], o: [V; 1]) -> V {
            let ([a, b], [c]) = (i, o);
            a + b - c
        }
    }
    impl Add {
        pub fn add<CS>(cs: &mut CS, a: CS::V, b: CS::V) -> CS::V
        where
            CS: ConstraintSystem,
        {
            //let [c] = Add::run(cs, [a, b]);
            let [c] = cs.execute::<Self, 3, 2, 1>([a, b]);
            c
        }
    }

    pub struct Zero;
    impl Gate<2, 2, 0> for Zero {
        fn gate<V: Var>(_: [V; 2]) -> [V; 0] {
            []
        }
        fn check<V: Var>(i: [V; 2], _: [V; 0]) -> V {
            let [a, b] = i;
            a - b
        }
    }
    #[test]
    fn cs() {
        let mut cs = ExperimentalConstraintSystem::<3>::new();
        let a = cs.var();
        let b = cs.var();
        let [c] = cs.execute::<Add, 3, 2, 1>([a, b]);
        // let [c] = Add2::run(&mut cs, [a, b]);
        let _d = Add::add(&mut cs, a, c);

        println!("cs: {:#?}", cs);
    }
}
