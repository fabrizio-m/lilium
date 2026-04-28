use crate::{
    challenges::{ChallIdx, SparkChallenges},
    spark2::evals::{kinds, DimensionIndex, SparkIndex, SparkOpen},
};
use ark_ff::Field;
use std::fmt::Debug;
use sumcheck::sumcheck::{Env, EvalKind, SumcheckFunction, Var};

#[derive(Clone, Copy, Debug)]
pub struct SparkOpenSumcheck<const N: usize>;

impl<F: Field, const N: usize> SumcheckFunction<F> for SparkOpenSumcheck<N> {
    type Idx = SparkIndex;

    type Mles<V: Copy + Debug> = SparkOpen<V, N>;

    type Challs = SparkChallenges<F>;

    type ChallIdx = ChallIdx;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(f)
    }

    fn function<V, E>(_env: E) -> V
    where
        V: Var<F>,
        E: Env<F, V, Self::Idx, Self::ChallIdx>,
    {
        panic!("unused")
    }

    fn symbolic_function<V, E>(&self, env: E) -> Option<V>
    where
        V: Var<F>,
        E: Env<F, V, Self::Idx, Self::ChallIdx>,
    {
        //     1
        // Σ -----
        //   f + µ
        let get = |i, idx| env.get(SparkIndex::Dimension(idx, i));

        let chall = env.get_chall(ChallIdx::Combination);

        let mut checks = form_check(&env, 0);
        let mut eq = get(0, DimensionIndex::EqLookup);

        for i in 1..N {
            let check = form_check(&env, i);
            checks = checks * chall.clone() + check;
            let eq_segment = get(i, DimensionIndex::EqLookup);
            eq = eq * eq_segment;
        }

        let eval = eq * env.get(SparkIndex::Value);

        let zerocheck = env.get(SparkIndex::Zerocheck) * checks;
        let mut inverse_sums = zerocheck;

        for i in 0..N {
            let inverse = get(i, DimensionIndex::Inverse);
            inverse_sums = inverse_sums * chall.clone() + inverse;
        }

        // folding checks[0..N], sums[0..N], eval
        Some(inverse_sums * chall + eval)
    }
}

/// Constrains form to be
fn form_check<F, V, E>(env: E, i: usize) -> V
where
    F: Field,
    V: Var<F>,
    E: Env<F, V, SparkIndex, ChallIdx>,
{
    let get = |idx| env.get(SparkIndex::Dimension(idx, i));
    let address = get(DimensionIndex::Address);
    let lookup = get(DimensionIndex::EqLookup);

    let compression_chall = env.get_chall(ChallIdx::Compression);

    let indexed_lookup = address * compression_chall + lookup;

    let inverse = get(DimensionIndex::Inverse);

    let lookup_challenge = env.get_chall(ChallIdx::Lookup);

    let product = inverse * (indexed_lookup + lookup_challenge);

    product - F::one()
}
