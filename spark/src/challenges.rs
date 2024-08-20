use ark_ff::Field;

/// Challenges used in spark
#[derive(Debug, Default)]
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
