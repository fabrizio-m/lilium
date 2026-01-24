use ark_ff::Field;
use sumcheck::{
    polynomials::Evals,
    sumcheck::{Env, EvalKind, SumcheckFunction, Var},
    utils::ZeroCheckAvailable,
};

/// sumcheck based reduction of linearized instances
pub struct LinearizedSumcheck<const IO: usize>;

#[derive(Clone)]
pub struct LinearizedMles<V, const IO: usize> {
    /// matrix vector products M(x)z(x)
    pub products: [V; IO],
    pub r_eq: V,
}

impl<V, const IO: usize> LinearizedMles<V, IO> {
    pub fn new(products: [V; IO], r_eq: V) -> Self {
        Self { products, r_eq }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Index {
    /// M_i(rx,x)z(x) for the given i
    Product(usize),
    /// eq(rx).
    Req,
}

impl ZeroCheckAvailable for Index {
    fn zerocheck_eq() -> Self {
        Self::Req
    }
}

impl<V: Clone + Copy, const IO: usize> Evals<V> for LinearizedMles<V, IO> {
    type Idx = Index;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            Index::Product(i) => &self.products[i],
            Index::Req => &self.r_eq,
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let mut products = self.products;
        products.iter_mut().zip(other.products).for_each(|(a, b)| {
            *a = f(*a, b);
        });
        let r_eq = f(self.r_eq, other.r_eq);
        Self { products, r_eq }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        vec.extend(self.products);
        vec.push(self.r_eq);
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
        let [r_eq] = [elems.next().unwrap(); 1];
        Self { products, r_eq }
    }
}

const fn kinds<const IO: usize>() -> LinearizedMles<EvalKind, IO> {
    let products = [EvalKind::Virtual; IO];
    let r_eq = EvalKind::FixedSmall;
    LinearizedMles { products, r_eq }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SingleChall<F>(pub F);

impl<F> std::ops::Index<()> for SingleChall<F> {
    type Output = F;

    fn index(&self, _index: ()) -> &Self::Output {
        &self.0
    }
}

impl<F: Field, const IO: usize> SumcheckFunction<F> for LinearizedSumcheck<IO> {
    type Idx = Index;

    type Mles<V: Copy + std::fmt::Debug> = LinearizedMles<V, IO>;

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
        Self::Mles { products, r_eq }
    }

    fn function<V, E>(env: E) -> V
    where
        V: Var<F>,
        E: Env<F, V, Self::Idx, Self::ChallIdx>,
    {
        let chall = env.get_chall(());

        // let mut acc = inputs_check.0;
        let mut acc = env.get(Index::Product(0));
        for i in 1..IO {
            acc = acc * &chall;
            let m_eq = env.get(Index::Product(i));
            acc += &m_eq;
        }
        let req = env.get(Index::Req);
        acc * req
    }
}
