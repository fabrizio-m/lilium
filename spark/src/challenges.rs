use ark_ff::Field;

/// Challenges used in spark
#[derive(Debug, Default, Clone, Copy)]
pub struct SparkChallenges<F: Field> {
    /// The shift used in the denominator in lookups/multiset check
    lookup_challenge: F,
    /// used to combine multiple sucheck statements into one
    combination_challenge: F,
    /// Used to compress several polynomials into 1
    compression_challenge: F,
}

pub trait CompressionChallenge<F: Field> {
    fn compression_challenge(&self) -> &F;
}

pub trait LookupChallenge<F: Field> {
    fn lookup_challenge(&self) -> &F;
}
pub trait CombinationChallenge<F: Field> {
    fn combination_challenge(&self) -> &F;
}

impl<F: Field> CompressionChallenge<F> for SparkChallenges<F> {
    fn compression_challenge(&self) -> &F {
        &self.compression_challenge
    }
}

impl<F: Field> LookupChallenge<F> for SparkChallenges<F> {
    fn lookup_challenge(&self) -> &F {
        &self.lookup_challenge
    }
}

impl<F: Field> CombinationChallenge<F> for SparkChallenges<F> {
    fn combination_challenge(&self) -> &F {
        &self.combination_challenge
    }
}

impl<F: Field> SparkChallenges<F> {
    pub fn new(lookup_challenge: F, combination_challenge: F, compression_challenge: F) -> Self {
        Self {
            lookup_challenge,
            combination_challenge,
            compression_challenge,
        }
    }
}
