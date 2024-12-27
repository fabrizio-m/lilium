//! Traits for state machines, as I have few of them around.

// A transducer, a Mealy  machine
pub trait FiniteAutomata {
    /// type for initiallization, may be same as state
    type Init;
    type State;
    /// Use () for machines without inputs
    type Input;
    /// Leave as () to have just an fsm, no transducer
    type Output;
    fn init(init: Self::Init) -> Self;
    /// integrated transition and output function, mutating state
    /// ignore input when computing output for Moore machine.
    fn transition_mut(&mut self, input: Self::Input) -> Self::Output;
}
