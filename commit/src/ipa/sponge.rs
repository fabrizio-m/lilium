use ark_ec::Group;
use ark_ff::PrimeField;
use std::marker::PhantomData;

pub trait Sponge<F, G> {
    fn absorb_g(&mut self, x: G);
    fn absorb_f(&mut self, x: F);
    fn squeeze_f(&mut self) -> F;
    fn squeeze_g(&mut self) -> G;
}

pub struct SimpleSponge<F> {
    hasher: blake3::Hasher,
    _f: PhantomData<F>,
}
impl<F: PrimeField, G: Group> Sponge<F, G> for SimpleSponge<F> {
    fn absorb_g(&mut self, x: G) {
        let mut bytes = vec![];
        x.serialize_uncompressed(&mut bytes).unwrap();
        self.hasher.update(&bytes);
    }

    fn absorb_f(&mut self, x: F) {
        let mut bytes = vec![];
        x.serialize_uncompressed(&mut bytes).unwrap();
        self.hasher.update(&bytes);
    }

    fn squeeze_f(&mut self) -> F {
        let hash = self.hasher.finalize();
        // reabsorbing hash to work like a sponge
        self.hasher.update(hash.as_bytes());
        F::from_le_bytes_mod_order(hash.as_bytes())
    }

    fn squeeze_g(&mut self) -> G {
        let hash = self.hasher.finalize();
        // reabsorbing hash to work like a sponge
        self.hasher.update(hash.as_bytes());
        // just creating a scalar and scaling the generator
        // endomorphism recomposition would make more sense for real use cases
        let scalar = <G::ScalarField>::from_le_bytes_mod_order(hash.as_bytes());
        G::generator() * scalar
    }
}
