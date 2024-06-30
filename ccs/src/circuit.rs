use crate::{
    constraint_system::{cs_prototype::GateRegistry, ConstraintSystem},
    structure::{CcsStructure, StructureBuilder},
    witness::{unwrap_output, Witness, WitnessGenerator},
};
use ark_ff::Field;

pub trait Circuit<
    F: Field,
    C: ConstraintSystem,
    const IN: usize = 0,
    const OUT: usize = 0,
    const PRIV_OUT: usize = 0,
>
{
    ///() if you don't care
    type PrivateInput;
    ///() if you don't care
    type PrivateOutput;

    fn register_gates(registry: &mut GateRegistry);
    fn circuit(cs: &mut C, public_input: [C::V; IN]) -> ([C::V; OUT], [C::V; PRIV_OUT]);
    fn handle_output(out: [F; PRIV_OUT]) -> Self::PrivateOutput;
}
pub trait BuildStructure<
    F: Field,
    const IN: usize,
    const OUT: usize,
    const PRIV_OUT: usize,
    const IO: usize,
>: Circuit<F, StructureBuilder<IO>, IN, OUT, PRIV_OUT>
{
    fn structure<const S: usize>() -> CcsStructure<IO, S, F> {
        let (mut cs, public_input) = StructureBuilder::<IO>::with_inputs::<IN>();
        cs.register_gates(Self::register_gates);
        let (public_out, private_out) = Self::circuit(&mut cs, public_input);
        //unnecessary for this
        let _ = private_out;
        cs.link_outputs::<IN, OUT>(public_out);

        let structure = cs.build::<F, S>(IN + OUT);
        structure
    }
}

impl<T, F: Field, const IN: usize, const OUT: usize, const PRIV_OUT: usize, const IO: usize>
    BuildStructure<F, IN, OUT, PRIV_OUT, IO> for T
where
    T: Circuit<F, StructureBuilder<IO>, IN, OUT, PRIV_OUT>,
{
}

pub trait Prove<F: Field, const IN: usize, const OUT: usize, const PRIV_OUT: usize, const IO: usize>:
    Circuit<F, WitnessGenerator<F, IO>, IN, OUT, PRIV_OUT>
{
    fn witness(inputs: [F; IN], check: bool) -> (Witness<F>, Self::PrivateOutput) {
        let (mut cs, public_input) = WitnessGenerator::with_io::<IN, OUT>(check, inputs);
        let (public_out, private_out) = Self::circuit(&mut cs, public_input);
        let private_out = unwrap_output(private_out);

        cs.link_outputs::<IN, OUT>(public_out);
        (cs.witness(), Self::handle_output(private_out))
    }
}
impl<T, F: Field, const IN: usize, const OUT: usize, const PRIV_OUT: usize, const IO: usize>
    Prove<F, IN, OUT, PRIV_OUT, IO> for T
where
    T: Circuit<F, WitnessGenerator<F, IO>, IN, OUT, PRIV_OUT>,
{
}

mod test {
    use crate::{
        circuit::Circuit,
        constraint_system::{cs_prototype::Add, ConstraintSystem, Gate},
    };
    use ark_ff::Field;

    struct MyCircuit;
    impl<F: Field, C> Circuit<F, C, 2, 1, 1> for MyCircuit
    where
        C: ConstraintSystem,
    {
        type PrivateInput = ();

        type PrivateOutput = ();
        ///register the gates to be used in the circuit
        fn register_gates(registry: &mut crate::constraint_system::cs_prototype::GateRegistry) {
            Add::register(registry);
        }

        fn circuit(cs: &mut C, public_input: [C::V; 2]) -> ([C::V; 1], [C::V; 1]) {
            let [a, b] = public_input;
            let c = Add::add(cs, a, b);
            ([c.clone()], [c])
        }

        fn handle_output(_out: [F; 1]) -> Self::PrivateOutput {
            ()
        }
    }
    ///composition
    struct MyCircuit2;
    impl<F: Field, C> Circuit<F, C, 2, 1, 1> for MyCircuit2
    where
        C: ConstraintSystem,
        MyCircuit: Circuit<F, C, 2, 1, 1>,
    {
        type PrivateInput = ();

        type PrivateOutput = ();

        fn register_gates(registry: &mut crate::constraint_system::cs_prototype::GateRegistry) {
            MyCircuit::register_gates(registry);
        }

        fn circuit(cs: &mut C, public_input: [C::V; 2]) -> ([C::V; 1], [C::V; 1]) {
            let ([c], _) = MyCircuit::circuit(cs, public_input);

            ([c.clone()], [c])
        }

        fn handle_output(_out: [F; 1]) -> Self::PrivateOutput {
            ()
        }
    }
    // use super::{structure::CcsStructure, BuildStructure, Prove};

    // fn test<F: Field>() {
    // let struc: CcsStructure<3, 2, F> = MyCircuit::structure();
    // let (witness, _private_out) = MyCircuit::witness([F::one(), F::one()], false);
    // }
}
