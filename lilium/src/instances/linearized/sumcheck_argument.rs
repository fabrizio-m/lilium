use ark_ff::Field;
use sumcheck::{
    polynomials::Evals,
    sumcheck::{CommitType, Env, EvalKind, SumcheckFunction, Var},
    utils::ZeroCheckAvailable,
};

/// sumcheck based reduction of linearized instances
pub struct LinearizedSumcheck<const IO: usize>;

#[derive(Clone)]
pub struct LinearizedMles<V, const IO: usize> {
    /// M(rx,y)
    pub matrices: [V; IO],
    pub r_eq: V,
    pub z: V,
}

impl<V, const IO: usize> LinearizedMles<V, IO> {
    pub fn new(matrices: [V; IO], r_eq: V, z: V) -> Self {
        Self { matrices, r_eq, z }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Index {
    /// Matrix M_i(rx,x) for the given i.
    M(usize),
    /// eq(rx).
    Req,
    /// The witness.
    Z,
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
            Index::M(i) => &self.matrices[i],
            Index::Req => &self.r_eq,
            Index::Z => &self.z,
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let mut matrices = self.matrices;
        matrices.iter_mut().zip(other.matrices).for_each(|(a, b)| {
            *a = f(*a, b);
        });
        let r_eq = f(self.r_eq, other.r_eq);
        let z = f(self.z, other.z);
        Self { matrices, r_eq, z }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        vec.extend(self.matrices);
        vec.push(self.r_eq);
        vec.push(self.z);
    }

    fn unflatten(elems: &mut std::vec::IntoIter<V>) -> Self {
        let matrices = {
            let elems: Vec<V> = elems.take(IO).collect();
            match elems.try_into() {
                Ok(p) => p,
                Err(_) => {
                    panic!("not enough elements")
                }
            }
        };
        let r_eq = elems.next().unwrap();
        let z = elems.next().unwrap();
        Self { matrices, r_eq, z }
    }
}

const fn kinds<const IO: usize>() -> LinearizedMles<EvalKind, IO> {
    let matrices = [EvalKind::Virtual; IO];
    let r_eq = EvalKind::FixedSmall;
    let z = EvalKind::Committed(CommitType::Instance);
    LinearizedMles { matrices, r_eq, z }
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
        let matrices = evals.matrices.map(&f);
        let r_eq = f(evals.r_eq);
        let z = f(evals.z);
        Self::Mles { matrices, r_eq, z }
    }

    fn function<V, E>(env: E) -> V
    where
        V: Var<F>,
        E: Env<F, V, Self::Idx, Self::ChallIdx>,
    {
        let chall = env.get_chall(());
        let z = env.get(Index::Z);

        let mut acc = env.get(Index::M(0)) * &z;
        for i in 1..IO {
            acc = acc * &chall;
            let m_eq = env.get(Index::M(i)) * &z;
            acc += &m_eq;
        }
        let req = env.get(Index::Req);
        acc * req
    }
}
