use ark_ff::Field;
use sumcheck::{
    polynomials::Evals,
    sumcheck::{CommitType, Env, EvalKind, SumcheckFunction, Var},
    utils::{ZeroCheck, ZeroCheckAvailable},
};

/// sumcheck based reduction of linearized instances
pub struct LinearizedSumcheck<const IO: usize>;

#[derive(Clone)]
pub struct LinearizedMles<V, const IO: usize> {
    /// matrix vector products M(x)z(x)
    products: [V; IO],
    r_eq: V,
    w: V,
    inputs: V,
    input_selector: V,
}

impl<V, const IO: usize> LinearizedMles<V, IO> {
    pub fn new(products: [V; IO], r_eq: V, w: V, inputs: V, input_selector: V) -> Self {
        Self {
            products,
            r_eq,
            w,
            inputs,
            input_selector,
        }
    }
}

#[derive(Clone, Copy, Debug)]
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
}

impl ZeroCheckAvailable for Index {
    fn zerocheck_eq() -> Self {
        Self::Zeq
    }
}

impl<V: Clone + Copy, const IO: usize> Evals<V> for LinearizedMles<V, IO> {
    type Idx = Index;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            Index::Product(i) => &self.products[i],
            Index::Zeq => &self.r_eq,
            Index::W => &self.w,
            Index::Inputs => &self.inputs,
            Index::InputsSelector => &self.input_selector,
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let mut products = self.products.clone();
        products.iter_mut().zip(other.products).for_each(|(a, b)| {
            *a = f(*a, b);
        });
        let w = f(self.w, other.w);
        let r_eq = f(self.r_eq, other.r_eq);
        let inputs = f(self.inputs, other.inputs);
        let input_select = f(self.input_selector, other.input_selector);
        Self {
            products,
            r_eq,
            w,
            inputs,
            input_selector: input_select,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        vec.extend(self.products);
        vec.push(self.r_eq);
        vec.push(self.w);
        vec.push(self.inputs);
        vec.push(self.input_selector);
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
        let [r_eq, w, inputs, input_selector] = [elems.next().unwrap(); 4];
        Self {
            products,
            r_eq,
            w,
            inputs,
            input_selector,
        }
    }
}

const fn kinds<const IO: usize>() -> LinearizedMles<EvalKind, IO> {
    let products = [EvalKind::Virtual; IO];
    let r_eq = EvalKind::FixedSmall;
    let w = EvalKind::Committed(CommitType::Instance);
    let inputs = EvalKind::FixedSmall;
    let input_selector = EvalKind::FixedSmall;
    LinearizedMles {
        products,
        r_eq,
        w,
        inputs,
        input_selector,
    }
}

impl<F: Field, const IO: usize> SumcheckFunction<F> for LinearizedSumcheck<IO> {
    type Idx = Index;

    type Mles<V: Copy + std::fmt::Debug> = LinearizedMles<V, IO>;

    type Challs = F;

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
        Self::Mles {
            products,
            r_eq,
            w,
            inputs,
            input_selector,
        }
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E, challs: &Self::Challs) -> V {
        let chall = challs;
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
        for i in 0..IO {
            acc *= *chall;
            let m_eq = env.get(Index::Product(i));
            acc += &m_eq;
        }
        acc
    }
}
