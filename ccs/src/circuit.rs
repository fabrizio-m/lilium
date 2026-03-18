use std::fmt::Display;

use crate::{
    constraint_system::{ConstraintSystem, Val},
    structure::{CcsStructure, StructureBuilder},
    witness::{unwrap_output, Witness, WitnessGenerator},
};
use ark_ff::Field;

#[derive(Clone, Copy)]
/// Symbolic circuit variable.
pub struct Var<V>(pub(crate) V);

impl<F> Var<F> {
    pub(crate) fn unwrap(self) -> F {
        self.0
    }
}

/// Circuit definition, with generics for field, public inputs, and public and private outputs.
/// Private outputs being just a convenience to take value produced in the circuit out.
/// `Self::PrivateOutput` is to be generated from the private outputs when possible.
pub trait Circuit<F: Field, const IN: usize = 0, const OUT: usize = 0, const PRIV_OUT: usize = 0> {
    ///() if you don't care
    /// TODO: not currently usable.
    type PrivateInput;
    ///() if you don't care
    type PrivateOutput;

    fn circuit<V: Val, C: ConstraintSystem<V>>(
        cs: &mut C,
        public_input: [Var<V>; IN],
    ) -> ([Var<V>; OUT], [Var<V>; PRIV_OUT]);
    fn handle_output(out: [F; PRIV_OUT]) -> Self::PrivateOutput;
}

pub trait BuildStructure<
    F: Field,
    const IN: usize,
    const OUT: usize,
    const PRIV_OUT: usize,
    const IO: usize,
>: Circuit<F, IN, OUT, PRIV_OUT>
{
    fn structure<const S: usize>() -> CcsStructure<IO, S> {
        let (mut cs, public_input) = StructureBuilder::<IO>::with_inputs::<IN>();
        cs.reserve_outputs::<OUT>();
        let (public_out, private_out) = Self::circuit(&mut cs, public_input.map(Var));
        //unnecessary for this
        let _ = private_out;
        cs.link_outputs::<IN, OUT>(public_out.map(Var::unwrap));

        cs.build::<S>(IN + OUT)
    }

    fn profile() -> CircuitProfile {
        let (mut cs, public_input) = StructureBuilder::<IO>::with_inputs::<IN>();
        cs.reserve_outputs::<OUT>();
        let (public_out, _) = Self::circuit(&mut cs, public_input.map(Var));
        cs.link_outputs::<IN, OUT>(public_out.map(Var::unwrap));
        let gate_counts = cs.gate_counts();
        CircuitProfile { gate_counts }
    }
}

#[derive(Debug)]
pub struct CircuitProfile {
    gate_counts: Vec<(&'static str, usize)>,
}

impl Display for CircuitProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CircuitProfile\n")?;
        writeln!(f, "gates used:")?;
        for (gate, count) in &self.gate_counts {
            writeln!(f, "{}: {}", gate, count)?;
        }
        Ok(())
    }
}

impl<T, F: Field, const IN: usize, const OUT: usize, const PRIV_OUT: usize, const IO: usize>
    BuildStructure<F, IN, OUT, PRIV_OUT, IO> for T
where
    T: Circuit<F, IN, OUT, PRIV_OUT>,
{
}

pub trait Prove<F: Field, const IN: usize, const OUT: usize, const PRIV_OUT: usize, const IO: usize>:
    Circuit<F, IN, OUT, PRIV_OUT>
{
    fn witness(inputs: [F; IN], check: bool) -> (Witness<F>, Self::PrivateOutput) {
        let (mut cs, public_input) = WitnessGenerator::<F, IO>::with_io::<IN, OUT>(check, inputs);
        let (public_out, private_out) = Self::circuit(&mut cs, public_input.map(Var));
        let private_out = unwrap_output(private_out.map(Var::unwrap));

        cs.link_outputs::<IN, OUT>(public_out.map(Var::unwrap));
        (cs.witness(), Self::handle_output(private_out))
    }
}

impl<T, F: Field, const IN: usize, const OUT: usize, const PRIV_OUT: usize, const IO: usize>
    Prove<F, IN, OUT, PRIV_OUT, IO> for T
where
    T: Circuit<F, IN, OUT, PRIV_OUT>,
{
}

mod test {
    use crate::{
        circuit::{Circuit, Var},
        constraint_system::{cs_prototype::Add, ConstraintSystem, Val},
    };
    use ark_ff::Field;

    struct MyCircuit;

    impl<F: Field> Circuit<F, 2, 1, 1> for MyCircuit {
        type PrivateInput = ();

        type PrivateOutput = ();

        fn circuit<V: Val, C: ConstraintSystem<V>>(
            cs: &mut C,
            public_input: [super::Var<V>; 2],
        ) -> ([super::Var<V>; 1], [super::Var<V>; 1]) {
            let [a, b] = public_input;
            let c = Add::add(cs, a, b);
            ([c.clone()], [c])
        }

        fn handle_output(_out: [F; 1]) -> Self::PrivateOutput {}
    }

    // Composition.

    struct MyCircuit2;

    impl<F: Field> Circuit<F, 2, 1, 1> for MyCircuit2
    where
        MyCircuit: Circuit<F, 2, 1, 1>,
    {
        type PrivateInput = ();

        type PrivateOutput = ();

        fn circuit<V: Val, C: ConstraintSystem<V>>(
            cs: &mut C,
            public_input: [Var<V>; 2],
        ) -> ([Var<V>; 1], [Var<V>; 1]) {
            let ([c], _) = MyCircuit::circuit(cs, public_input);

            ([c.clone()], [c])
        }

        fn handle_output(_out: [F; 1]) -> Self::PrivateOutput {}
    }
}
