use std::ops::Index;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChallIdx {
    /// The shift used in the denominator in lookups/multiset check
    LookupChallenge,
    /// used to combine multiple sucheck statements into one
    CombinationChallenge,
    /// Used to compress several polynomials into 1
    CompressionChallenge,
}

impl<F: Field> Index<ChallIdx> for SparkChallenges<F> {
    type Output = F;

    fn index(&self, index: ChallIdx) -> &Self::Output {
        use ChallIdx::*;
        match index {
            LookupChallenge => &self.lookup_challenge,
            CombinationChallenge => &self.combination_challenge,
            CompressionChallenge => &self.compression_challenge,
        }
    }
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

impl<F: Field> SparkChallenges<F> {
    pub fn new(lookup_challenge: F, combination_challenge: F, compression_challenge: F) -> Self {
        Self {
            lookup_challenge,
            combination_challenge,
            compression_challenge,
        }
    }
}
