use crate::instances::{eval_input_selector, eval_ux};
use ark_ff::Field;
use ccs::structure::Exp;
use std::{fmt::Debug, marker::PhantomData};
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::{CommitType, Env, EvalKind, SumcheckFunction, Var},
    zerocheck::{ZeroCheckIdx, ZeroCheckMles},
};

/// sumcheck based reduction of lcs instances
pub struct LcsSumcheck<F, const IO: usize, const S: usize> {
    gates: Vec<Vec<Exp<usize>>>,
    _f: PhantomData<F>,
}

impl<F, const IO: usize, const S: usize> LcsSumcheck<F, IO, S> {
    pub fn new(gates: Vec<Vec<Exp<usize>>>) -> Self {
        Self {
            gates,
            _f: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LcsMles<V, const IO: usize, const S: usize> {
    /// matrix vector products M(x)z(x)
    products: [V; IO],
    // zerocheck: V,
    w: V,
    inputs: V,
    input_selector: V,
    gate_selectors: [V; S],
}

impl<V, const IO: usize, const S: usize> Default for LcsMles<Option<V>, IO, S> {
    fn default() -> Self {
        Self {
            products: [(); IO].map(|_| None),
            w: None,
            inputs: None,
            input_selector: None,
            gate_selectors: [(); S].map(|_| None),
        }
    }
}

impl<V, const IO: usize, const S: usize> LcsMles<V, IO, S> {
    pub fn new_structure(input_selector: V, gate_selectors: [V; S]) -> Self
    where
        V: Field,
    {
        Self {
            products: [V::zero(); IO],
            w: V::zero(),
            inputs: V::zero(),
            input_selector,
            gate_selectors,
        }
    }

    pub fn products(&self) -> &[V; IO] {
        &self.products
    }

    pub fn gate_selectors(&self) -> &[V; S] {
        &self.gate_selectors
    }

    pub fn w(&self) -> &V {
        &self.w
    }

    /// Create eval with provided products and everything else set to `None`.
    pub fn new_only_products(products: [V; IO]) -> LcsMles<Option<V>, IO, S> {
        let products = products.map(Option::Some);
        LcsMles {
            products,
            ..LcsMles::default()
        }
    }

    pub fn from_committed_evals(w: V, selector_evals: [V; S]) -> LcsMles<Option<V>, IO, S> {
        LcsMles {
            w: Some(w),
            gate_selectors: selector_evals.map(Some),
            ..Default::default()
        }
    }

    pub(crate) fn small_evals<F: Field>(
        point: MultiPoint<F>,
        inputs: Vec<F>,
    ) -> LcsMles<Option<F>, IO, S> {
        let input_len = inputs.len();

        let u = F::one();
        let inputs = eval_ux(point.inner_ref(), u, &inputs);
        let inputs = Some(inputs);

        let input_selector = eval_input_selector(&point, input_len);
        let input_selector = Some(input_selector);

        LcsMles {
            products: [None; IO],
            w: None,
            inputs,
            input_selector,
            gate_selectors: [None; S],
        }
    }

    pub fn set_instance_witness_evals(&mut self, products: [V; IO], w: V, inputs: Option<V>) {
        self.products = products;
        self.w = w;
        if let Some(inputs) = inputs {
            self.inputs = inputs;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum Index {
    /// M_i(rx,x)z(x) for the given i
    Product(usize),
    /// Witness
    W,
    /// Including u at the start.
    Inputs,
    /// 1 where input expected, 0 otherwise
    InputsSelector,
    GateSelector(usize),
}

impl<V: Copy, const IO: usize, const S: usize> Evals<V> for LcsMles<V, IO, S> {
    type Idx = Index;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            Index::Product(i) => &self.products[i],
            Index::W => &self.w,
            Index::Inputs => &self.inputs,
            Index::InputsSelector => &self.input_selector,
            Index::GateSelector(i) => &self.gate_selectors[i],
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let mut products = self.products;
        products.iter_mut().zip(other.products).for_each(|(a, b)| {
            *a = f(*a, b);
        });
        let w = f(self.w, other.w);
        let inputs = f(self.inputs, other.inputs);
        let input_selector = f(self.input_selector, other.input_selector);

        let mut gate_selectors = self.gate_selectors;
        gate_selectors
            .iter_mut()
            .zip(other.gate_selectors)
            .for_each(|(a, b)| {
                *a = f(*a, b);
            });

        Self {
            products,
            w,
            inputs,
            input_selector,
            gate_selectors,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        vec.extend(self.products);
        vec.push(self.w);
        vec.push(self.inputs);
        vec.push(self.input_selector);
        vec.extend(self.gate_selectors);
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
        let [w, inputs, input_selector] = [(); 3].map(|_| elems.next().unwrap());
        let gate_selectors = [(); S].map(|_| elems.next().unwrap());

        Self {
            products,
            w,
            inputs,
            input_selector,
            gate_selectors,
        }
    }
}

const fn kinds<const IO: usize, const S: usize>(
) -> ZeroCheckMles<EvalKind, LcsMles<EvalKind, IO, S>> {
    let products = [EvalKind::Virtual; IO];
    let w = EvalKind::Committed(CommitType::Instance);
    let inputs = EvalKind::FixedSmall;
    let input_selector = EvalKind::FixedSmall;
    let gate_selectors = [EvalKind::Committed(CommitType::Structure); S];

    let inner = LcsMles {
        products,
        w,
        inputs,
        input_selector,
        gate_selectors,
    };
    ZeroCheckMles::new(EvalKind::FixedSmall, inner)
}

#[derive(Clone, Debug, Default)]
pub struct ConstraintCombinationChallenge<F>(F);

impl<F> From<F> for ConstraintCombinationChallenge<F> {
    fn from(value: F) -> Self {
        Self(value)
    }
}

impl<F> core::ops::Index<()> for ConstraintCombinationChallenge<F> {
    type Output = F;

    fn index(&self, _index: ()) -> &Self::Output {
        &self.0
    }
}

impl<F, const IO: usize, const S: usize> SumcheckFunction<F> for LcsSumcheck<F, IO, S>
where
    F: Field,
{
    type Idx = ZeroCheckIdx<Index>;

    type Mles<V: Copy + Debug> = ZeroCheckMles<V, LcsMles<V, IO, S>>;

    type Challs = ConstraintCombinationChallenge<F>;

    type ChallIdx = ();

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(&f, |inner| {
            let products = inner.products.map(&f);
            let w = f(inner.w);
            let inputs = f(inner.inputs);
            let input_selector = f(inner.input_selector);
            let gate_selectors = inner.gate_selectors.map(&f);
            LcsMles {
                products,
                w,
                inputs,
                input_selector,
                gate_selectors,
            }
        })
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(_env: E) -> V {
        panic!("unused")
    }

    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        env: E,
    ) -> Option<V> {
        let inner = |idx| env.get(ZeroCheckIdx::Inner(idx));
        let chall = env.get_chall(());
        let w = inner(Index::W);

        let inputs_check = {
            let inputs = inner(Index::Inputs);
            let input_selec = inner(Index::InputsSelector);
            // equality enforced with the public inputs in the
            // part of the domain dedicated to them.
            input_selec * &w - inputs
        };

        let mut acc = inputs_check;
        for (i, constraints) in self.gates.iter().enumerate() {
            let selector = inner(Index::GateSelector(i));
            for constraint in constraints {
                let exp = constraint.clone();
                acc = acc * &chall + eval_exp(&env, exp) * &selector;
            }
        }
        Some(acc)
    }
}

fn eval_exp<F, V, E>(env: &E, exp: Exp<usize>) -> V
where
    F: Field,
    V: Var<F>,
    E: Env<F, V, ZeroCheckIdx<Index>, ()>,
{
    match exp {
        Exp::Atom(v) => env.get(ZeroCheckIdx::Inner(Index::Product(v))),
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
    }
}

/// Same as `LcsSumcheck` without the zerocheck wrapper, as required for folding.
pub struct LcsSumfold<F, const IO: usize, const S: usize> {
    gates: Vec<Vec<Exp<usize>>>,
    _f: PhantomData<F>,
}

impl<F: Field, const IO: usize, const S: usize> From<LcsSumcheck<F>> for LcsSumfold<F, IO, S> {
    fn from(value: LcsSumcheck<F>) -> Self {
        let LcsSumcheck { gates, _f };
        LcsSumfold { gates, _f }
    }
}

impl<F, const IO: usize, const S: usize> SumcheckFunction<F> for LcsSumfold<F, IO, S>
where
    F: Field,
{
    type Idx = Index;

    type Mles<V: Copy + Debug> = LcsMles<V, IO, S>;

    type Challs = ConstraintCombinationChallenge<F>;

    type ChallIdx = ();

    const KINDS: Self::Mles<EvalKind> = *kinds().inner();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        let products = evals.products.map(&f);
        let w = f(evals.w);
        let inputs = f(evals.inputs);
        let input_selector = f(evals.input_selector);
        let gate_selectors = evals.gate_selectors.map(&f);
        LcsMles {
            products,
            w,
            inputs,
            input_selector,
            gate_selectors,
        }
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(_env: E) -> V {
        panic!("unused")
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
            input_selec * &w - inputs
        };

        let mut acc = inputs_check;
        for (i, constraints) in self.gates.iter().enumerate() {
            let selector = env.get(Index::GateSelector(i));
            for constraint in constraints {
                let exp = constraint.clone();
                acc = acc * &chall + eval_exp(&env, exp) * &selector;
            }
        }
        Some(acc)
    }
}
