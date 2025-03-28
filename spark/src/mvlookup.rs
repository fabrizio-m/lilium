use crate::challenges::LookupChallenge;
use ark_ff::Field;
use sumcheck::{
    polynomials::Evals,
    sumcheck::{CommitType, EvalKind, Var},
    utils::{ZeroCheck, ZeroSumcheck},
};

#[derive(Clone, Copy, Debug)]
pub enum LookupIdx {
    /// Claimed fraction for left side
    Frac1,
    /// Claimed fraction for right side
    Frac2,
    /// Counts of how many times a table element appears in the lookups
    Counts,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct LookupEval<V> {
    frac1: V,
    frac2: V,
    counts: V,
}

impl<V: Copy> Evals<V> for LookupEval<V> {
    type Idx = LookupIdx;

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let frac1 = f(self.frac1, other.frac1);
        let frac2 = f(self.frac2, other.frac2);
        let counts = f(self.counts, other.counts);
        LookupEval {
            frac1,
            frac2,
            counts,
        }
    }

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            LookupIdx::Frac1 => &self.frac1,
            LookupIdx::Frac2 => &self.frac2,
            LookupIdx::Counts => &self.counts,
        }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self {
            frac1,
            frac2,
            counts,
        } = self;
        vec.push(frac1);
        vec.push(frac2);
        vec.push(counts);
    }

    fn unflatten(elems: &mut std::vec::IntoIter<V>) -> Self {
        let frac1 = elems.next().unwrap();
        let frac2 = elems.next().unwrap();
        let counts = elems.next().unwrap();
        Self {
            frac1,
            frac2,
            counts,
        }
    }
}

fn shape_dynamic_count<F: Field, V: Var<F>>(set: V, counts: V, frac: V, chall: F) -> V {
    frac * (set + chall) - counts
}

fn shape_fixed_count<F: Field, V: Var<F>>(set: V, frac: V, chall: F) -> V {
    frac * (set + chall) - F::one()
}

/// Multiset equality check between 2 multisets
pub fn multiset_check<F, V>(
    multisets: (V, V),
    fracs: (V, V),
    chall: F,
) -> ([ZeroCheck<V>; 2], ZeroSumcheck<V>)
where
    F: Field,
    V: Var<F>,
{
    let (set1, set2) = multisets;
    let (frac1, frac2) = fracs;
    let left_check = shape_fixed_count(set1, frac1.clone(), chall);
    let right_check = shape_fixed_count(set2, frac2.clone(), chall);
    let equality = frac1 - frac2;
    (
        [ZeroCheck(left_check), ZeroCheck(right_check)],
        ZeroSumcheck(equality),
    )
}

/// Lookups where [counts] states how many times each element in the table
/// appears in the lookups
pub fn lookup<F, V, C>(
    lookups: V,
    table: V,
    counts: V,
    fracs: (V, V),
    challenges: &C,
) -> ([ZeroCheck<V>; 2], ZeroSumcheck<V>)
where
    F: Field,
    V: Var<F>,
    C: LookupChallenge<F>,
{
    let (frac1, frac2) = fracs;
    let chall = challenges.lookup_challenge();
    let left = shape_fixed_count(lookups, frac1, *chall);
    let right = shape_dynamic_count(table, counts, frac2, *chall);
    let equality = left.clone() - right.clone();
    let zero_checks = [left, right].map(ZeroCheck);
    (zero_checks, ZeroSumcheck(equality))
}

impl<V> LookupEval<V> {
    pub const fn kind() -> LookupEval<EvalKind> {
        let [frac1, frac2, counts] = [EvalKind::Committed(CommitType::Structure); 3];
        LookupEval {
            frac1,
            frac2,
            counts,
        }
    }

    pub fn map<B, M>(self, f: M) -> LookupEval<B>
    where
        B: Copy + std::fmt::Debug,
        M: Fn(V) -> B,
    {
        let Self {
            frac1,
            frac2,
            counts,
        } = self;
        let frac1 = f(frac1);
        let frac2 = f(frac2);
        let counts = f(counts);
        LookupEval {
            frac1,
            frac2,
            counts,
        }
    }
}
impl<F: Field> LookupEval<F> {
    pub fn evals(lookups: &[F], table: &[F], counts: &[F], challenge: F) -> Vec<Self> {
        assert_eq!(lookups.len(), table.len());
        assert_eq!(lookups.len(), counts.len());
        let mut left_den: Vec<F> = lookups.iter().map(|x| *x + challenge).collect();
        ark_ff::fields::batch_inversion(&mut left_den);
        let frac1 = left_den;
        let mut right_den: Vec<F> = table.iter().map(|x| *x + challenge).collect();
        ark_ff::fields::batch_inversion(&mut right_den);

        counts
            .iter()
            .zip(frac1)
            .zip(right_den)
            .map(|x| {
                let ((counts, frac1), right_den) = x;
                let frac2 = right_den * counts;
                LookupEval {
                    frac1,
                    counts: *counts,
                    frac2,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    const VARS: usize = 8;
    const EVALS: usize = 1 << VARS;
    use crate::{
        challenges::{CombinationChallenge, SparkChallenges},
        mvlookup::LookupEval,
    };
    use ark_ff::Field;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sumcheck::{
        polynomials::{simple_eval::SimpleEval, MultiPoint},
        prove_and_verify,
        sumcheck::{Env, EvalKind, SumcheckFunction, Var},
        utils::ZeroCheckAvailable,
    };

    struct RangeCheck;

    // 0: zero_check
    // 1: lookups
    // 2: table
    // 3: counts
    // 4: fracs_1
    // 5: fracs_2
    type Evals<F> = SimpleEval<F, 6>;

    impl<F: Field> SumcheckFunction<F> for RangeCheck {
        type Idx = usize;

        type Mles<V: Copy + std::fmt::Debug> = Evals<V>;

        // reusing them as we need the same here
        type Challs = SparkChallenges<F>;

        const KINDS: Self::Mles<EvalKind> = Evals::new([EvalKind::FixedSmall; 6]);

        fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E, challs: &Self::Challs) -> V {
            // let zero_check = env.get(0);
            let lookups = env.get(1);
            let table = env.get(2);
            let counts = env.get(3);
            let fracs_1 = env.get(4);
            let fracs_2 = env.get(5);
            let fracs = (fracs_1, fracs_2);
            let ([c1, c2], c3) = super::lookup(lookups, table, counts, fracs, challs);
            let c1 = ZeroCheckAvailable::zero_check(&env, c1);
            let c2 = ZeroCheckAvailable::zero_check(&env, c2);

            let comb_chall = challs.combination_challenge();
            let checks = c1.0;
            let checks = (checks * *comb_chall) + c2.0;
            let checks = (checks * *comb_chall) + c3.0;
            checks
        }

        fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
        where
            A: Copy + std::fmt::Debug,
            B: Copy + std::fmt::Debug,
            M: Fn(A) -> B,
        {
            Evals::map(evals, f)
        }
    }

    fn lookups<R: Rng>(rng: &mut R) -> Vec<u32> {
        let mut lookup = || rng.gen::<u32>() % (EVALS as u32);
        vec![lookup(); EVALS]
    }

    fn rangecheck_test<F: Field>() {
        let mut rng = StdRng::seed_from_u64(4);
        let table: Vec<u32> = (0..(EVALS as u32)).collect();
        let lookups = lookups(&mut rng);
        let mut counts = vec![0_u32; EVALS];
        for lookup in lookups.clone() {
            counts[lookup as usize] += 1;
        }
        let [table, lookups, counts] =
            [table, lookups, counts].map(|x| x.into_iter().map(F::from).collect::<Vec<F>>());

        let lookup_challenge = F::rand(&mut rng);
        let combination_challenge = F::rand(&mut rng);
        let compression_challenge = F::rand(&mut rng);
        let challenge = SparkChallenges::new(
            lookup_challenge,
            combination_challenge,
            compression_challenge,
        );
        let mut elem = || F::rand(&mut rng);
        let zero_check_point = vec![elem(); VARS];
        let zero_check_point = MultiPoint::new(zero_check_point);

        let lookup_evals = LookupEval::evals(&lookups, &table, &counts, lookup_challenge);
        let mut evals = vec![];
        let zero_eq = sumcheck::eq::eq(&zero_check_point);

        for i in 0..EVALS {
            let lookup = lookups[i];
            let table = table[i];
            // let counts = counts[i];
            let LookupEval {
                frac1,
                frac2,
                counts,
            } = lookup_evals[i];
            let zero_check = zero_eq[i];
            let eval = [zero_check, lookup, table, counts, frac1, frac2];
            evals.push(SimpleEval::new(eval));
        }
        let sum = F::zero();
        prove_and_verify::<F, RangeCheck>(evals, sum, challenge);
    }
    #[test]
    fn rangecheck() {
        use ark_vesta::Fq;
        rangecheck_test::<Fq>();
    }
}
