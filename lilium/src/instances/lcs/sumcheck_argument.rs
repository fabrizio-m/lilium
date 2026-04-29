use ark_ff::Field;
use ccs::structure::Exp;
use std::marker::PhantomData;
use sumcheck::{
    polynomials::Evals,
    sumcheck::{CommitType, Env, EvalKind, SumcheckFunction, Var},
    utils::{ZeroCheck, ZeroCheckAvailable},
};

/// sumcheck based reduction of lcs instances
pub struct LcsSumcheck<F, const IO: usize, const S: usize> {
    //gates: Constraints<Exp<usize>>,
    gates: Vec<Vec<Exp<usize>>>,
    _f: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct LcsMles<V, const IO: usize, const S: usize> {
    /// matrix vector products M(x)z(x)
    products: [V; IO],
    r_eq: V,
    w: V,
    inputs: V,
    input_selector: V,
    gate_selectors: [V; S],
    constants: V,
}

impl<V, const IO: usize, const S: usize> Default for LcsMles<Option<V>, IO, S> {
    fn default() -> Self {
        Self {
            products: [(); IO].map(|_| None),
            r_eq: None,
            w: None,
            inputs: None,
            input_selector: None,
            gate_selectors: [(); S].map(|_| None),
            constants: None,
        }
    }
}

impl<V, const IO: usize, const S: usize> LcsMles<V, IO, S> {
    pub fn new_structure(input_selector: V, gate_selectors: [V; S], constants: V) -> Self
    where
        V: Field,
    {
        Self {
            products: [V::zero(); IO],
            r_eq: V::zero(),
            w: V::zero(),
            inputs: V::zero(),
            input_selector,
            gate_selectors,
            constants,
        }
    }

    pub fn gate_selectors(&self) -> &[V; S] {
        &self.gate_selectors
    }

    /// Returns (input_selector, gate_selectors).
    pub fn selectors(&self) -> (V, [V; S])
    where
        V: Copy,
    {
        (self.input_selector, self.gate_selectors)
    }

    pub fn constants(&self) -> V
    where
        V: Copy,
    {
        self.constants
    }

    pub fn set_w(&mut self, w: V) {
        self.w = w;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum Index {
    /// M_i(rx,x)z(x) for the given i
    Product(usize),
    /// eq(r) on r random point for zero check
    Zeq,
    /// Witness
    W,
    /// Including u at the start.
    Inputs,
    /// 1 where input expected, 0 otherwise
    InputsSelector,
    GateSelector(usize),
    Constants,
}

impl ZeroCheckAvailable for Index {
    fn zerocheck_eq() -> Self {
        Self::Zeq
    }
}

impl<V: Clone + Copy, const IO: usize, const S: usize> Evals<V> for LcsMles<V, IO, S> {
    type Idx = Index;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            Index::Product(i) => &self.products[i],
            Index::Zeq => &self.r_eq,
            Index::W => &self.w,
            Index::Inputs => &self.inputs,
            Index::InputsSelector => &self.input_selector,
            Index::GateSelector(i) => &self.gate_selectors[i],
            Index::Constants => &self.constants,
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let mut products = self.products;
        products.iter_mut().zip(other.products).for_each(|(a, b)| {
            *a = f(*a, b);
        });
        let w = f(self.w, other.w);
        let r_eq = f(self.r_eq, other.r_eq);
        let inputs = f(self.inputs, other.inputs);
        let input_selector = f(self.input_selector, other.input_selector);

        let mut gate_selectors = self.gate_selectors;
        gate_selectors
            .iter_mut()
            .zip(other.gate_selectors)
            .for_each(|(a, b)| {
                *a = f(*a, b);
            });
        let constants = f(self.constants, other.constants);

        Self {
            products,
            r_eq,
            w,
            inputs,
            input_selector,
            gate_selectors,
            constants,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        vec.extend(self.products);
        vec.push(self.r_eq);
        vec.push(self.w);
        vec.push(self.inputs);
        vec.push(self.input_selector);
        vec.extend(self.gate_selectors);
        vec.push(self.constants);
    }

    fn unflatten(elems: &mut std::vec::IntoIter<V>) -> Self {
        let products = {
            let elems: Vec<V> = elems.take(IO).collect();
            match elems.try_into() {
                Ok(p) => p,
                Err(_) => {
                    panic!("not enough elements")
                }
            }
        };
        let [r_eq, w, inputs, input_selector] = [(); 4].map(|_| elems.next().unwrap());
        let gate_selectors = [(); S].map(|_| elems.next().unwrap());
        let constants = elems.next().unwrap();

        Self {
            products,
            r_eq,
            w,
            inputs,
            input_selector,
            gate_selectors,
            constants,
        }
    }
}

const fn kinds<const IO: usize, const S: usize>() -> LcsMles<EvalKind, IO, S> {
    let products = [EvalKind::Virtual; IO];
    let r_eq = EvalKind::FixedSmall;
    let w = EvalKind::Committed(CommitType::Instance);
    let inputs = EvalKind::FixedSmall;
    let input_selector = EvalKind::FixedSmall;
    let gate_selectors = [EvalKind::Committed(CommitType::Structure); S];
    let constants = EvalKind::Committed(CommitType::Structure);

    LcsMles {
        products,
        r_eq,
        w,
        inputs,
        input_selector,
        gate_selectors,
        constants,
    }
}

#[derive(Debug, Default, Clone, Copy)]
//TODO: get from sumcheck crate
pub struct SingleChall<F>(F);

impl<F> From<F> for SingleChall<F> {
    fn from(value: F) -> Self {
        SingleChall(value)
    }
}

impl<F> core::ops::Index<()> for SingleChall<F> {
    type Output = F;

    fn index(&self, _index: ()) -> &Self::Output {
        &self.0
    }
}

impl<F: Field, const IO: usize, const S: usize> SumcheckFunction<F> for LcsSumcheck<F, IO, S> {
    type Idx = Index;

    type Mles<V: Copy + std::fmt::Debug> = LcsMles<V, IO, S>;

    type ChallIdx = ();

    type Challs = SingleChall<F>;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + std::fmt::Debug,
        B: Copy + std::fmt::Debug,
        M: Fn(A) -> B,
    {
        let products = evals.products.map(&f);
        let r_eq = f(evals.r_eq);
        let w = f(evals.w);
        let inputs = f(evals.inputs);
        let input_selector = f(evals.input_selector);
        let gate_selectors = evals.gate_selectors.map(&f);
        let constants = f(evals.constants);
        Self::Mles {
            products,
            r_eq,
            w,
            inputs,
            input_selector,
            gate_selectors,
            constants,
        }
    }

    fn function<V, E>(_env: E) -> V
    where
        V: Var<F>,
        E: Env<F, V, Self::Idx, Self::ChallIdx>,
    {
        todo!()
    }

    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        env: E,
    ) -> Option<V> {
        let chall = env.get_chall(());
        let w = env.get(Index::W);

        let inputs_check = {
            let inputs = env.get(Index::Inputs);
            let input_selec = env.get(Index::InputsSelector);
            // equality enforced with the public inputs in the
            // part of the domain dedicated to them.
            let zero_check = ZeroCheck(input_selec * &w - inputs);
            Index::zero_check(&env, zero_check)
        };

        let mut acc = inputs_check.0;
        for (i, constraints) in self.gates.iter().enumerate() {
            let selector = env.get(Index::GateSelector(i));
            for constraint in constraints {
                let exp = if matches!(constraint, Exp::Constant) {
                    let product = env.get(Index::Product(0));
                    let constants = env.get(Index::Constants);
                    product - constants
                } else {
                    let exp = constraint.clone();
                    eval_exp(&env, exp)
                };
                acc = acc * &chall + exp * &selector;
            }
        }
        Some(acc)
    }
}

fn eval_exp<F, V, E>(env: &E, exp: Exp<usize>) -> V
where
    F: Field,
    V: Var<F>,
    E: Env<F, V, Index, ()>,
{
    match exp {
        Exp::Atom(v) => env.get(Index::Product(v)),
        Exp::Add(exp1, exp2) => {
            let e1 = eval_exp(env, *exp1);
            let e2 = eval_exp(env, *exp2);
            e1 + e2
        }
        Exp::Mul(exp1, exp2) => {
            let e1 = eval_exp(env, *exp1);
            let e2 = eval_exp(env, *exp2);
            e1 * e2
        }
        Exp::Sub(exp1, exp2) => {
            let e1 = eval_exp(env, *exp1);
            let e2 = eval_exp(env, *exp2);
            e1 - e2
        }
        Exp::Constant => panic!("Constant shouldn't have been evaluated"),
    }
}
