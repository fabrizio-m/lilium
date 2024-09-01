use crate::{
    challenges::{CombinationChallenge, CompressionChallenge, LookupChallenge, SparkChallenges},
    evals::{DimensionIndex, SparkEval, SparkIndex},
    mvlookup::{self, LookupIdx},
};
use ark_ff::Field;
use sumcheck::{
    sumcheck::{Env, SumcheckFunction, Var},
    utils::{ZeroAvailable, ZeroCheckAvailable},
};

pub struct SparkEvalCheck<const D: usize>;

impl<F: Field, const D: usize> SumcheckFunction<F> for SparkEvalCheck<D> {
    type Idx = SparkIndex;
    type Mles = SparkEval<F, D>;
    type Challs = SparkChallenges<F>;

    fn function<V, E>(env: E, challs: &SparkChallenges<F>) -> V
    where
        V: Var<F>,
        E: Env<F, V, Self::Idx>,
    {
        let normal_index = env.get(SparkIndex::NormalIndex);
        let val = env.get(SparkIndex::Val);
        let mut eval = val;
        let mut all_checks = env.get(SparkIndex::zero());
        let combination_challenge = *challs.combination_challenge();
        for i in 0..D {
            let (dim, checks) = dimension(&env, i, normal_index.clone(), challs);

            for check in checks {
                // TODO: should be handled without unwrapping
                all_checks += &check.0;
                all_checks *= combination_challenge;
            }
            eval = dim * eval;
        }
        all_checks * combination_challenge + eval
    }
}

fn dimension<F, V, E, C>(
    env: E,
    i: usize,
    normal_index: V,
    challenges: &C,
) -> (V, [sumcheck::utils::ZeroSumcheck<V>; 3])
where
    F: Field,
    V: Var<F>,
    E: Env<F, V, SparkIndex>,
    C: CompressionChallenge<F> + LookupChallenge<F>,
{
    let idx = |x| SparkIndex::Dimension(i, x);
    let dimension_index = idx(DimensionIndex::Dimension);
    let dimension_lookups = idx(DimensionIndex::EqLookup);
    let eq_eval = idx(DimensionIndex::EqEval);

    let idx = |x| idx(DimensionIndex::Lookup(x));
    let frac1 = idx(LookupIdx::Frac1);
    let frac2 = idx(LookupIdx::Frac2);
    let counts = idx(LookupIdx::Counts);

    let counts = env.get(counts);
    let fracs = (env.get(frac1), env.get(frac2));

    let eq_evals = env.get(eq_eval);

    let table = collapse_columns(normal_index, eq_evals, challenges);
    let dimension_index = env.get(dimension_index);
    let dimension_lookups = env.get(dimension_lookups);
    let lookups = collapse_columns(dimension_index, dimension_lookups.clone(), challenges);

    let ([c1, c2], c3) = mvlookup::lookup(lookups, table, counts, fracs, challenges);
    let checks = [
        SparkIndex::zero_check(&env, c1),
        SparkIndex::zero_check(&env, c2),
        c3,
    ];
    (dimension_lookups, checks)
}

fn collapse_columns<F, V, C>(a: V, b: V, challenges: &C) -> V
where
    F: Field,
    V: Var<F>,
    C: CompressionChallenge<F>,
{
    let challenge = challenges.compression_challenge();
    a + b * *challenge
}
