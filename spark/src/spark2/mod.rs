use crate::spark2::{evals::SparkOpen, sumcheck_argument::SparkOpenSumcheck};
use ark_ff::Field;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use std::rc::Rc;
use sumcheck::sumcheck::SumcheckVerifier;

mod evals;
pub mod flexible;
mod prove;
mod reduction;
mod sumcheck_argument;
mod trusted_commit;

pub use prove::ProverOutput;

const BYTE: usize = 256;

#[derive(Clone, Debug)]
pub struct SparkSparseMle<F, const N: usize> {
    /// Addresses in u8 segments.
    addresses: Vec<[u8; N]>,
    /// The value at given address.
    values: Vec<F>,
    /// How many times each address segement is referenced.
    /// Any may be 0, but each segment must sum up to the number of lookups.
    counts: [Box<[usize; BYTE]>; N],
}

/*struct SparkTrustedCommitment<F, C, const N: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    values: C::Commitment,
    addresses: [C::Commitment; N],
}*/

#[derive(Clone, Debug)]
struct MinorStructure<const N: usize> {
    counts: [Box<[usize; BYTE]>; N],
}

#[derive(Clone, Debug)]
pub struct CommittedSpark<F: Field, C: CommmitmentScheme<F>, const N: usize> {
    committed_structure: CommittedStructure<F, SparkOpenSumcheck<N>, C>,
    minor_structure: MinorStructure<N>,
    major_structure: Rc<Vec<SparkOpen<F, N>>>,
    sumcheck_verifier: SumcheckVerifier<F, SparkOpenSumcheck<N>>,
    mle: Rc<SparkSparseMle<F, N>>,
}

type StructureEvals<F, const N: usize> = ([F; N], F);
type InstanceEvals<F, const N: usize> = [[F; 2]; N];

#[derive(Debug, Clone)]
pub struct CommittedSparkProof<F: Field, C: CommmitmentScheme<F>, const N: usize> {
    eq_lookup_commitments: [C::Commitment; N],
    fraction_lookup_commitments: [C::Commitment; N],
    sumcheck_proof: sumcheck::sumcheck::Proof<F, SparkOpenSumcheck<N>>,
    structure_evals: StructureEvals<F, N>,
    instance_evals: InstanceEvals<F, N>,
}

// t' = eq(r,x)
// t = (0..256) * t'
// f = addr * eq
//
//      m           1
//  Σ -----  = Σ  -----
//    t + µ       f + µ
//
// for the right:
// r_inv = 1 / (f + µ)
// check that r_inv * (f + µ) == 1
