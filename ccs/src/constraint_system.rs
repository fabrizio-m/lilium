use crate::{circuit::Var, structure::Exp};
use std::ops;

/// Capability token that allows reading the field element behind a `Var<F>`.
pub struct WitnessAccess(());

impl WitnessAccess {
    pub(crate) fn new() -> Self {
        WitnessAccess(())
    }
}

pub trait ConstraintSystem<F, V> {
    fn execute<G, const IO: usize, const I: usize, const O: usize>(
        &mut self,
        i: [Var<V>; I],
    ) -> [Var<V>; O]
    where
        G: Gate<IO, I, O> + 'static,
        V: Val;

    /// Read the witness value under the variable, the token should be available
    /// only
    fn read(&self, var: &Var<V>, token: &WitnessAccess) -> F;
    /// Creates a new variable with the provided value.
    /// The variable is not constrained to have the provided value, or any
    /// particular value at all.
    /// The value is provided through a function which receives a [WitnessAccess]
    /// token and may use it to call [ConstraintSystem::read] to access the value
    /// behind a [Var<F>].
    /// While calling this method means you already have `&mut ConstraintSystem`,
    /// you wouldn't be able to call [ConstraintSystem::read] as that would create
    /// a `&ConstraintSystem` at the same time. For that reason `&mut ConstraintSystem`
    /// is provided again to you as an argument for `W`.
    fn free_variable<W>(&mut self, value: W) -> Var<V>
    where
        W: for<'a> FnOnce(&mut Self, &'a WitnessAccess) -> F;
}

pub trait Val:
    ops::Add<Output = Self> + ops::Mul<Output = Self> + ops::Sub<Output = Self> + Clone + Sized
{
}

/// A non-empty list of constraints.
#[derive(Debug, Clone)]
pub enum Constraints<V> {
    Constraint(V),
    Append(Box<Self>, V),
    Empty,
}

impl<V> From<V> for Constraints<V> {
    fn from(value: V) -> Self {
        Self::Constraint(value)
    }
}

impl<V: Copy> Iterator for Constraints<V> {
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Constraints::Constraint(c) => {
                let c = *c;
                *self = Constraints::Empty;
                Some(c)
            }
            Constraints::Append(constraints, c) => {
                let c = *c;
                let dummy = Box::new(Constraints::Constraint(c));
                let constraints = *std::mem::replace(constraints, dummy);
                *self = constraints;
                Some(c)
            }
            Constraints::Empty => None,
        }
    }
}

impl<V, const N: usize> From<[V; N]> for Constraints<V> {
    fn from(value: [V; N]) -> Self {
        assert!(N > 0, "must have at least one constraint");
        let mut values = value.into_iter();
        let first: Self = values.next().unwrap().into();
        values.fold(first, |acc, c| Constraints::Append(Box::new(acc), c))
    }
}

impl<V> From<Constraints<V>> for Vec<V> {
    fn from(value: Constraints<V>) -> Self {
        // Not the most efficient, but it isn't performance critical anyway.
        match value {
            Constraints::Constraint(c) => vec![c],
            Constraints::Append(tail, head) => {
                let mut constraints: Vec<V> = From::from(*tail);
                constraints.push(head);
                constraints
            }
            Constraints::Empty => vec![],
        }
    }
}

/// A gate, which maps inputs to outputs, and defines one or more constraints
/// between both inputs and outputs.
/// `Self::gate` deals only with witness generation, while `Self::check` defines
/// the actual constraints to be enforced.
pub trait Gate<const IO: usize, const I: usize, const O: usize>: Sized + 'static {
    /// Computes outputs from inputs.
    fn gate<V: Val>(i: [V; I]) -> [V; O];
    /// The output should be zero when the constraint is satisfied.
    /// use `into()` to convert either `V` or `[V;N]` into required output.
    fn check<V: Val>(i: [V; I], o: [V; O]) -> Constraints<V>;
}

fn eval_gate_constraints<G, const IO: usize, const I: usize, const O: usize>(
) -> Constraints<Exp<usize>>
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
        any::{type_name, Any, TypeId},
        collections::BTreeMap,
    };

    #[derive(Debug)]
    /// Keeps track of used gates, and assigns a unique id to each of them.
    pub struct GateRegistry {
        pub(crate) gate_registry: BTreeMap<TypeId, (usize, Constraints<Exp<usize>>, &'static str)>,
        next_selector: usize,
    }

    impl Default for GateRegistry {
        fn default() -> Self {
            let gate_registry = BTreeMap::new();
            Self {
                gate_registry,
                //TODO: may reserve 0 for equality
                next_selector: 0,
            }
        }
    }

    impl GateRegistry {
        pub fn selector<G, const IO: usize, const I: usize, const O: usize>(&mut self) -> usize
        where
            G: Any + Gate<IO, I, O>,
        {
            let id = TypeId::of::<G>();
            let entry = self.gate_registry.entry(id);
            let entry = entry.or_insert_with(|| {
                self.next_selector += 1;
                let exp = eval_gate_constraints::<G, IO, I, O>();
                (self.next_selector - 1, exp, type_name::<G>())
            });
            entry.0
        }
    }

    /// An addition gate.
    pub struct Add;
    impl Gate<3, 2, 1> for Add {
        fn gate<V: Val>([a, b]: [V; 2]) -> [V; 1] {
            //let c = a + b;
            [a + b]
        }

        fn check<V: Val>(i: [V; 2], o: [V; 1]) -> Constraints<V> {
            let ([a, b], [c]) = (i, o);
            (a + b - c).into()
        }
    }
    impl Add {
        pub fn add<F, V: Val, CS>(cs: &mut CS, a: Var<V>, b: Var<V>) -> Var<V>
        where
            CS: ConstraintSystem<F, V>,
        {
            //let [c] = Add::run(cs, [a, b]);
            let [c] = cs.execute::<Self, 3, 2, 1>([a, b]);
            c
        }
    }

    /// An equality gate.
    pub struct Equality;
    impl Gate<2, 2, 0> for Equality {
        fn gate<V: Val>(_: [V; 2]) -> [V; 0] {
            []
        }
        fn check<V: Val>(i: [V; 2], _: [V; 0]) -> Constraints<V> {
            let [a, b] = i;
            (a - b).into()
        }
    }
}
