use crate::structure::Exp;
use std::ops;

pub trait ConstraintSystem {
    type V: Var;

    fn execute<G, const IO: usize, const I: usize, const O: usize>(
        &mut self,
        i: [Self::V; I],
    ) -> [Self::V; O]
    where
        G: Gate<IO, I, O> + 'static;
}

pub trait Var:
    ops::Add<Output = Self> + ops::Mul<Output = Self> + ops::Sub<Output = Self> + Clone + Sized
{
}
pub trait Gate<const IO: usize, const I: usize, const O: usize>: Sized + 'static {
    //type Inputs: InputTrait + HasInputs<I>;
    //type Outputs: OutputTrait + HasOutputs<O> + AtLeast<IO>;

    ///computes outputs from inputs
    fn gate<V: Var>(i: [V; I]) -> [V; O];
    ///the output should be zero when the constraint is satisfied
    fn check<V: Var>(i: [V; I], o: [V; O]) -> V;
}

fn eval_gate_constraint<G, const IO: usize, const I: usize, const O: usize>() -> Exp<usize>
where
    G: Gate<IO, I, O>,
{
    let mut i = 0;
    let mut var = |_| {
        let e = Exp::Atom(i);
        i += 1;
        e
    };
    let i = [(); I].map(&mut var);
    let o = [(); O].map(&mut var);
    G::check(i, o)
}

pub mod cs_prototype {
    use super::*;
    use crate::structure::Exp;
    use std::{
        any::{Any, TypeId},
        collections::BTreeMap,
    };

    #[derive(Debug)]
    pub struct GateRegistry {
        //hashmap may not be the best
        pub(crate) gate_registry: BTreeMap<TypeId, (usize, Exp<usize>)>,
        next_selector: usize,
    }

    impl GateRegistry {
        pub fn new() -> Self {
            GateRegistry {
                gate_registry: BTreeMap::new(),
                //may reserve 0 for equality
                next_selector: 0,
            }
        }
        pub fn selector<G, const IO: usize, const I: usize, const O: usize>(&mut self) -> usize
        where
            G: Any + Gate<IO, I, O>,
        {
            let id = TypeId::of::<G>();
            let entry = self.gate_registry.entry(id);
            let entry = entry.or_insert_with(|| {
                self.next_selector += 1;
                let exp = eval_gate_constraint::<G, IO, I, O>();
                (self.next_selector, exp)
            });
            entry.0
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
}
