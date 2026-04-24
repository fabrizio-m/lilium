use crate::spark2::{
    evals::SparkOpen, sumcheck_argument::SparkOpenSumcheck, CommittedSpark, MinorStructure,
    SparkSparseMle, BYTE,
};
use ark_ff::Field;
use commit::{committed_structure::CommittedStructure, CommmitmentScheme};
use std::rc::Rc;
use sumcheck::sumcheck::SumcheckVerifier;

impl<const N: usize> MinorStructure<N> {
    fn new<F: Field>(mle: &SparkSparseMle<F, N>) -> Self {
        MinorStructure {
            counts: mle.counts.clone(),
        }
    }
}

impl<F, const N: usize> SparkSparseMle<F, N> {
    pub fn new(addresses: Vec<[u8; N]>, values: Vec<F>) -> Self {
        let mut counts: [Box<[usize; 256]>; N] =
            [(); N].map(|_| (vec![0; BYTE]).into_boxed_slice().try_into().unwrap());

        for (i, counts) in counts.iter_mut().enumerate() {
            for addr in addresses.iter() {
                let segment = addr[i];
                counts[segment as usize] += 1;
            }
        }

        Self {
            addresses,
            values,
            counts,
        }
    }
}

impl<F: Field, C: CommmitmentScheme<F>, const N: usize> CommittedSpark<F, C, N> {
    pub fn new(mle: Rc<SparkSparseMle<F, N>>, scheme: &C) -> Self {
        assert_eq!(mle.addresses.len(), mle.values.len());
        let vars = mle.addresses.len().ilog2() as usize;
        let structure = mle
            .addresses
            .iter()
            .zip(mle.values.iter())
            .map(|(addr, val)| SparkOpen::new_structure(*val, *addr))
            .collect();
        let major_structure = Rc::new(structure);
        let committed_structure = CommittedStructure::new(Rc::clone(&major_structure), scheme);

        let minor_structure = MinorStructure::new(&mle);
        let sumcheck_verifier: SumcheckVerifier<F, SparkOpenSumcheck<N>> =
            SumcheckVerifier::new(vars);

        Self {
            committed_structure,
            minor_structure,
            major_structure,
            sumcheck_verifier,
            mle,
        }
    }
}
