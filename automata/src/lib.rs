//! Traits for state machines, as I have few of them around.

mod fsm;
pub mod memory_machine;
pub mod stack_machine;

pub use fsm::FiniteAutomaton;
