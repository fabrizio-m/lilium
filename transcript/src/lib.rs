//! transcript implementation.

use ark_ff::Field;
use sponge::sponge::{Duplex, SpongeBuilder};
use std::{
    any::{Any, TypeId},
    marker::PhantomData,
    vec::IntoIter,
};

pub trait Message<F: Field> {
    fn len(vars: usize) -> usize;
    fn to_field_elements(&self) -> Vec<F>;
}

pub struct TranscriptBuilder<F: Field> {
    rounds: Vec<(TypeId, usize)>,
    vars: usize,
    sponge_builder: SpongeBuilder,
    _f: PhantomData<F>,
}

/// special type to generate points
struct PointRound;

impl<F: Field> Message<F> for PointRound {
    fn len(_vars: usize) -> usize {
        0
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![]
    }
}

impl<F: Field> TranscriptBuilder<F> {
    pub fn new(vars: usize) -> Self {
        let sponge_builder = SpongeBuilder::new();
        Self {
            rounds: vec![],
            vars,
            sponge_builder,
            _f: PhantomData,
        }
    }
    pub fn round<T: Any + Message<F>, const N: usize>(self) -> Self {
        let Self {
            mut rounds,
            sponge_builder,
            vars,
            ..
        } = self;
        let id = TypeId::of::<T>();
        rounds.push((id, N));

        let sponge_builder = sponge_builder
            .absorb(T::len(vars).try_into().unwrap())
            .squeeze(N.try_into().unwrap());

        Self {
            rounds,
            sponge_builder,
            vars,
            _f: PhantomData,
        }
    }
    pub fn point(self) -> Self {
        let Self {
            mut rounds,
            vars,
            sponge_builder,
            ..
        } = self;
        let round = (TypeId::of::<PointRound>(), vars);
        rounds.push(round);
        let sponge_builder = sponge_builder.squeeze(vars.try_into().unwrap());
        Self {
            rounds,
            vars,
            sponge_builder,
            _f: PhantomData,
        }
    }
    pub fn finish<S: Duplex<F>>(self) -> TranscriptDescriptor<F, S> {
        let Self {
            rounds,
            sponge_builder,
            vars,
            _f,
        } = self;
        let sponge = S::from_builder(sponge_builder);
        TranscriptDescriptor {
            sponge,
            rounds,
            vars,
        }
    }
}

pub struct TranscriptDescriptor<F: Field, S: Duplex<F>> {
    sponge: S::Initializer,
    rounds: Vec<(TypeId, usize)>,
    vars: usize,
}

impl<F: Field, S: Duplex<F>> TranscriptDescriptor<F, S> {
    pub fn instanciate(&self) -> Transcript<F, S> {
        let sponge = S::instanciate(&self.sponge);
        let rounds = self.rounds.clone().into_iter();
        Transcript {
            sponge,
            rounds,
            vars: self.vars,
            _f: PhantomData,
        }
    }
}
pub struct Transcript<F: Field, S: Duplex<F>> {
    sponge: S,
    rounds: IntoIter<(TypeId, usize)>,
    vars: usize,
    _f: PhantomData<F>,
}

#[derive(Debug)]
pub enum Error {
    SpongeError(sponge::Error),
    /// Attempt to send a message when no more messages were expected
    TranscriptFinished,
    /// Unexpected message or number of challenges generated
    UnexpectedMessage,
}

impl<F: Field, S: Duplex<F>> Transcript<F, S> {
    pub fn send_message<T, const N: usize>(&mut self, message: &T) -> Result<[F; N], Error>
    where
        T: Any + Message<F>,
    {
        let id = message.type_id();
        let elems = message.to_field_elements();
        for elem in elems.into_iter() {
            let _ = self.sponge.absorb(elem).map_err(Error::SpongeError)?;
        }
        let round = self.rounds.next().ok_or(Error::TranscriptFinished)?;
        if round != (id, N) {
            return Err(Error::UnexpectedMessage);
        }
        let challenges = [(); N].map(|_| self.sponge.squeeze().map_err(Error::SpongeError));
        let challenges: Result<Vec<F>, Error> = challenges.into_iter().collect();
        let challenges: [F; N] = challenges?.try_into().unwrap();
        Ok(challenges)
    }
    /// generates a multivariate point
    pub fn point(&mut self) -> Result<Vec<F>, Error> {
        let round = self.rounds.next().ok_or(Error::TranscriptFinished)?;
        let id = TypeId::of::<PointRound>();
        if round != (id, self.vars) {
            return Err(Error::UnexpectedMessage);
        }
        let challenges = (0..self.vars).map(|_| self.sponge.squeeze().map_err(Error::SpongeError));
        challenges.into_iter().collect()
    }
}
