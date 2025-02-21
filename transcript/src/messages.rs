use std::marker::PhantomData;

use crate::{params::ParamResolver, Message};
use ark_ff::{BigInteger, Field, PrimeField};

impl<F: Field> Message<F> for () {
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        0
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![]
    }
}
impl<F: Field, M: Message<F>, const N: usize> Message<F> for [M; N] {
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        M::len(vars, param_resolver) * N
    }

    fn to_field_elements(&self) -> Vec<F> {
        self.iter().flat_map(|x| x.to_field_elements()).collect()
    }
}

/// special type to generate points
pub(crate) struct PointRound;

impl<F: Field> Message<F> for PointRound {
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        0
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![]
    }
}

/// Element of F2 represented as 2 elements of F1
struct ForeignElement<F1, F2> {
    limbs: [F1; 2],
    _f2: PhantomData<F2>,
}

impl<F1, F2> From<F2> for ForeignElement<F1, F2>
where
    F1: PrimeField,
    F2: PrimeField,
{
    fn from(value: F2) -> Self {
        let bit_diff = F2::MODULUS_BIT_SIZE - F1::MODULUS_BIT_SIZE;
        assert!(bit_diff < 8, "fields differ in size in more than a byte");
        let mut bytes = value.into_bigint().to_bytes_le();
        let high_byte = bytes.pop().unwrap();
        let low = F1::from_le_bytes_mod_order(&bytes);
        let bytes = [high_byte];
        let high = F1::from_le_bytes_mod_order(&bytes);
        let limbs = [low, high];
        Self {
            limbs,
            _f2: PhantomData,
        }
    }
}
impl<F1, F2> Message<F1> for ForeignElement<F1, F2>
where
    F1: Field,
    F2: Field,
{
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        2
    }

    fn to_field_elements(&self) -> Vec<F1> {
        self.limbs.to_vec()
    }
}
