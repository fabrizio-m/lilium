use crate::{
    evals::{DimensionIndex, SparkEval, SparkIndex},
    mvlookup::{self, LookupIdx},
};
use ark_ff::Field;
use sumcheck::{
    sumcheck::{Env, SumcheckFunction, Var},
    utils::ZeroCheckAvailable,
};

struct SparkEvalCheck<const D: usize>;

/// Challenges used in spark
#[derive(Debug, Default)]
struct SparkChallenges<F: Field> {
    /// The shift used in the denominator in lookups/multiset check
    lookup_challenge: F,
    /// used to combine multiple sucheck statements into one
    combination_challenge: F,
    /// Used to compress several polynomials into 1
    compression_challenge: F,
}

impl<F: Field, const D: usize> SumcheckFunction<F> for SparkEvalCheck<D> {
    type Idx = SparkIndex;
    type Mles = SparkEval<F, D>;
    type Challs = SparkChallenges<F>;

    fn function<V, E>(env: E, _challs: &SparkChallenges<F>) -> V
    where
        V: Var<F>,
        E: Env<F, V, Self::Idx>,
    {
        let normal_index = env.get(SparkIndex::NormalIndex);
        let val = env.get(SparkIndex::Val);
        let mut eval = val;
        for i in 0..D {
            let (dim, checks) = dimension(&env, i, normal_index.clone());
            eval = dim * eval;
        }
        eval
    }
}

fn dimension<F, V, E>(
    env: E,
    i: usize,
    normal_index: V,
) -> (V, [sumcheck::utils::ZeroSumcheck<V>; 3])
where
    F: Field,
    V: Var<F>,
    E: Env<F, V, SparkIndex>,
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
    let compression_challenge = compression_challenge();

    let table = collapse_columns(normal_index, eq_evals, compression_challenge);
    let dimension_index = env.get(dimension_index);
    let dimension_lookups = env.get(dimension_lookups);
    let lookups = collapse_columns(
        dimension_index,
        dimension_lookups.clone(),
        compression_challenge,
    );

    let lookup_challenge = lookup_challenge();
    let ([c1, c2], c3) = mvlookup::lookup(lookups, table, counts, fracs, lookup_challenge);
    let checks = [
        SparkIndex::zero_check(&env, c1),
        SparkIndex::zero_check(&env, c2),
        c3,
    ];
    (dimension_lookups, checks)
}

fn lookup_challenge<F>() -> F {
    todo!()
}

fn compression_challenge<F>() -> F {
    todo!()
}

fn collapse_columns<F, V>(a: V, b: V, challenge: F) -> V
where
    F: Field,
    V: Var<F>,
{
    a + b * challenge
}
