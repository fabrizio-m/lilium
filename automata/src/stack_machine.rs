/// Stack from which elements cab bu popped.
pub struct PopableStack<'a, T> {
    pub(crate) stack: &'a mut Vec<T>,
}

/// Stach to which elements can be pushed.
pub struct PushableStack<'a, T, const N: usize> {
    pub(crate) stack: &'a mut Vec<T>,
}

impl<'a, T> PopableStack<'a, T> {
    /// Pop P elements, returning the elements and a stack to which
    /// N elements can bu pushed.
    pub fn pop<const P: usize, const N: usize>(self) -> ([T; P], PushableStack<'a, T, N>) {
        let Self { stack } = self;
        let elems = [(); P].map(|_| stack.pop().unwrap());
        let stack = PushableStack { stack };
        (elems, stack)
    }
}

/// Type that must be returned at the end of each transition
/// to ensure elements poped and pushed from the stack as
/// expected.
pub struct End(());

impl<'a, T, const N: usize> PushableStack<'a, T, N> {
    /// Pushes N elements, gives back `End` needed to return from transition.
    pub fn push(self, elems: [T; N]) -> End {
        self.stack.extend(elems);
        End(())
    }
}

/// Stack machine, types aim to guarantee control flow remaining constant for a given
/// program, allowing to bound the stack for a given program.
/// It can be considered as a pushdown automaton for arbitrary programns, and a fsm for
/// a given program.
pub trait StackMachine {
    /// Type of stack elements.
    type StackElem;
    type Instruction;
    /// Machine transition, control flow should depend only on the instraction.
    /// The stack enforces that by allowing to pop N elements once, and at the
    /// same time determining how many elements will be pushed.
    /// Finally, this function must return `End`, which can only be obtained
    /// by pushing the defined number of elements.
    fn transition(instruction: &Self::Instruction, stack: PopableStack<Self::StackElem>) -> End;
    /// Runs instructions, returning final stack.
    fn run_program(
        program: &[Self::Instruction],
        initial_stack: Vec<Self::StackElem>,
    ) -> Vec<Self::StackElem> {
        let mut stack: Vec<Self::StackElem> = initial_stack;
        for instruction in program {
            let stack = PopableStack { stack: &mut stack };
            let _ = Self::transition(instruction, stack);
        }
        stack
    }
    /// Finds the smallest stack size for the given program.
    fn bound_program(program: &[Self::Instruction], initial_stack: Vec<Self::StackElem>) -> usize {
        let mut stack: Vec<Self::StackElem> = initial_stack;
        let mut bound = stack.len();
        for instruction in program {
            let stack_wrapped = PopableStack { stack: &mut stack };
            let _ = Self::transition(instruction, stack_wrapped);
            bound = stack.len().max(bound);
        }
        bound
    }
}
