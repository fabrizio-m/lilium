use crate::{params::ParamResolver, Message};
use ark_ff::PrimeField;
use ark_ff::{BigInteger, Field};
use std::marker::PhantomData;

impl<F: Field> Message<F> for () {
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        0
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SingleElement<F>(pub F);

impl<F> SingleElement<F> {
    pub fn inner(self) -> F {
        self.0
    }
}

impl<F: Field> Message<F> for SingleElement<F> {
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        1
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![self.0]
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

/// Element of F1 represented as 2 elements of F2
pub struct ForeignElement<F1, F2> {
    pub value: F1,
    _f2: PhantomData<F2>,
}

impl<F1, F2> From<F1> for ForeignElement<F1, F2>
where
    F1: Field,
    F2: Field,
{
    fn from(value: F1) -> Self {
        let bit_diff = F2::BasePrimeField::MODULUS_BIT_SIZE as i32
            - F1::BasePrimeField::MODULUS_BIT_SIZE as i32;
        let bit_diff = bit_diff.unsigned_abs();
        assert!(bit_diff < 8, "fields differ in size in more than a byte");

        Self {
            value,
            _f2: PhantomData,
        }
    }
}
impl<F1, F2> Message<F2> for ForeignElement<F1, F2>
where
    F1: Field,
    F2: Field,
{
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        2
    }

    fn to_field_elements(&self) -> Vec<F2> {
        let (low, high) = self
            .value
            .to_base_prime_field_elements()
            .map(|x| {
                let mut bytes = x.into_bigint().to_bytes_le();
                let high_byte = bytes.pop().unwrap();
                let low = F2::BasePrimeField::from_le_bytes_mod_order(&bytes);
                let high = F2::BasePrimeField::from_le_bytes_mod_order(&[high_byte]);
                (low, high)
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let low = F2::from_base_prime_field_elems(&low).unwrap();
        let high = F2::from_base_prime_field_elems(&high).unwrap();
        vec![low, high]
    }
}

impl<F: Field, A: Message<F>, B: Message<F>> Message<F> for (A, B) {
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        A::len(vars, param_resolver) + B::len(vars, param_resolver)
    }

    fn to_field_elements(&self) -> Vec<F> {
        let a = self.0.to_field_elements();
        let b = self.1.to_field_elements();
        a.into_iter().chain(b).collect()
    }
}
