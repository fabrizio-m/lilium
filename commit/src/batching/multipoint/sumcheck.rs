use ark_ff::Field;
use std::{fmt::Debug, ops::Index};
use sumcheck::sumcheck::{CommitType, Env, EvalKind, SumcheckFunction, Var};

use crate::batching::multipoint::{
    MultipointBatching, MultipointChall, MultipointEvals, MultipointIdx,
};

const fn kinds<const N: usize>() -> [MultipointEvals<EvalKind>; N] {
    [MultipointEvals {
        eq: EvalKind::FixedSmall,
        poly: EvalKind::Committed(CommitType::Instance),
    }; N]
}

impl<F: Field, C, const N: usize> SumcheckFunction<F> for MultipointBatching<C, N> {
    type Idx = (usize, MultipointIdx);

    type Mles<V: Copy + Debug> = [MultipointEvals<V>; N];

    type Challs = MultipointChall<F>;

    type ChallIdx = ();

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(|e| {
            let MultipointEvals { eq, poly } = e;
            MultipointEvals {
                eq: f(eq),
                poly: f(poly),
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
        let chall = env.get_chall(());
        let first_eq = env.get((0, MultipointIdx::Eq));
        let first_poly = env.get((0, MultipointIdx::Poly));
        let first = first_eq * first_poly;

        let all_evals = (1..N).fold(first, |acc, i| {
            let eq = env.get((i, MultipointIdx::Eq));
            let poly = env.get((i, MultipointIdx::Poly));
            acc * chall.clone() + (poly * eq)
        });
        Some(all_evals)
    }
}

impl<F> Index<()> for MultipointChall<F> {
    type Output = F;

    fn index(&self, _: ()) -> &Self::Output {
        &self.0
    }
}
