use crate::{
    polynomials::Evals,
    sumcheck::{Env, EvalKind, NoChallIdx, NoChallenges, SumcheckFunction, Var},
    tests::prove_and_verify,
};
use ark_vesta::Fr;
use rand::{thread_rng, Rng};
use std::fmt::Debug;

#[derive(Clone, Copy)]
struct Eval<V = Fr> {
    a: V,
    b: V,
    c: V,
}

impl<V: Copy> Evals<V> for Eval<V> {
    type Idx = usize;

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let a = f(self.a, other.a);
        let b = f(self.b, other.b);
        let c = f(self.c, other.c);
        Eval { a, b, c }
    }

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            0 => &self.a,
            1 => &self.b,
            2 => &self.c,
            _ => {
                unreachable!()
            }
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self { a, b, c } = self;
        vec.push(a);
        vec.push(b);
        vec.push(c);
    }

    fn unflatten(elems: &mut std::vec::IntoIter<V>) -> Self {
        let a = elems.next().unwrap();
        let b = elems.next().unwrap();
        let c = elems.next().unwrap();
        Self { a, b, c }
    }
}

fn map_evals<A, B, M>(evals: Eval<A>, f: M) -> Eval<B>
where
    A: Copy,
    B: Copy,
    M: Fn(A) -> B,
{
    let Eval { a, b, c } = evals;
    let a = f(a);
    let b = f(b);
    let c = f(c);
    Eval { a, b, c }
}
struct MulGate;
impl SumcheckFunction<Fr> for MulGate {
    type Idx = usize;
    type Mles<V: Copy + Debug> = Eval<V>;
    type ChallIdx = NoChallIdx;
    type Challs = NoChallenges<Fr>;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn function<V: Var<Fr>, E: Env<Fr, V, Self::Idx, Self::ChallIdx>>(
        env: E,
        _challs: &NoChallenges<Fr>,
    ) -> V {
        let a = env.get(0);
        let b = env.get(1);
        let c = env.get(2);
        (a.clone() * b) - c
    }

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        map_evals(evals, f)
    }
}

const fn kinds() -> Eval<EvalKind> {
    Eval {
        a: EvalKind::FixedSmall,
        b: EvalKind::FixedSmall,
        c: EvalKind::FixedSmall,
    }
}
struct SquareGate;
impl SumcheckFunction<Fr> for SquareGate {
    type Idx = usize;
    type Mles<V: Copy + Debug> = Eval<V>;
    type ChallIdx = NoChallIdx;
    type Challs = NoChallenges<Fr>;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn function<V: Var<Fr>, E: Env<Fr, V, Self::Idx, Self::ChallIdx>>(
        env: E,
        _challs: &NoChallenges<Fr>,
    ) -> V {
        let a = env.get(0);
        a.clone() * a
    }

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        map_evals(evals, f)
    }
}

#[test]
fn sumcheck_mul() {
    let vars = 8;
    let domain_size = 1 << vars;
    let mut rng = thread_rng();
    let mut rand_fr = || rng.gen::<Fr>();
    let mut rand_eval = || {
        let a = rand_fr();
        let b = rand_fr();
        let c = a * b;
        Eval { a, b, c }
    };
    let mle: Vec<Eval> = (0..domain_size).map(|_| rand_eval()).collect();

    let sum = Fr::from(0);
    prove_and_verify::<Fr, MulGate>(mle, sum, NoChallenges::<Fr>::default());
}
#[test]
fn sumcheck_square() {
    let vars = 3;
    let domain_size = 1 << vars;
    let mut rng = thread_rng();
    let mut rand_fr = || rng.gen::<Fr>();
    let mut sumc = Fr::from(0);
    let mut rand_eval = || {
        let a = rand_fr();
        let (b, c) = (a, a);
        sumc += a * a;
        Eval { a, b, c }
    };
    let mle: Vec<Eval> = (0..domain_size).map(|_| rand_eval()).collect();
    prove_and_verify::<Fr, SquareGate>(mle, sumc, NoChallenges::<Fr>::default());
}
