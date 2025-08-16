use crate::{messages::PointRound, Error, Message};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::{
    any::{Any, TypeId},
    marker::PhantomData,
    vec::IntoIter,
};

pub struct Transcript<F: Field, S: Duplex<F>> {
    sponge: S,
    rounds: IntoIter<(TypeId, usize)>,
    vars: usize,
    _f: PhantomData<F>,
}

impl<F: Field, S: Duplex<F>> Transcript<F, S> {
    pub fn guard<P>(&mut self, proof: P) -> TranscriptGuard<F, S, P> {
        TranscriptGuard::new(self, proof)
    }

    pub(crate) fn new(sponge: S, rounds: IntoIter<(TypeId, usize)>, vars: usize) -> Self {
        Self {
            sponge,
            rounds,
            vars,
            _f: PhantomData,
        }
    }

    pub fn send_message<T, const N: usize>(&mut self, message: &T) -> Result<[F; N], Error>
    where
        T: Any + Message<F>,
    {
        let id = message.type_id();
        let elems = message.to_field_elements();
        for elem in elems.into_iter() {
            self.sponge.absorb(elem).map_err(Error::SpongeError)?;
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
    pub fn finish(self) -> Result<(), Error> {
        self.sponge.finish().map_err(Error::SpongeError)
    }
    pub fn finish_unchecked(self) {
        if let Err(err) = self.finish() {
            println!("{:#?}", err);
            panic!();
        }
    }
}

/// Wraps transcript and proof, ensuring no message circumvents
/// the transcript.
pub struct TranscriptGuard<'a, F: Field, S: Duplex<F>, P> {
    transcript: &'a mut Transcript<F, S>,
    proof: P,
}

/// wrapper to prevent values accidentally bypassing the transcript
pub struct MessageGuard<I>(I);

impl<I> From<I> for MessageGuard<I> {
    fn from(value: I) -> Self {
        Self(value)
    }
}

impl<I> MessageGuard<I> {
    pub fn new(inner: I) -> Self {
        MessageGuard(inner)
    }
}

impl<I> MessageGuard<Vec<I>> {
    pub fn transpose(self) -> Vec<MessageGuard<I>> {
        self.0.into_iter().map(MessageGuard).collect()
    }
}

impl<I, const N: usize> MessageGuard<[I; N]> {
    pub fn transpose(self) -> [MessageGuard<I>; N] {
        self.0.map(MessageGuard)
    }
}

impl<'a, F: Field, S: Duplex<F>, P> TranscriptGuard<'a, F, S, P> {
    pub fn new(transcript: &'a mut Transcript<F, S>, proof: P) -> Self {
        Self { transcript, proof }
    }

    pub fn new_guard<P2>(
        &mut self,
        proof: impl Into<MessageGuard<P2>>,
    ) -> TranscriptGuard<F, S, P2> {
        let proof: MessageGuard<P2> = proof.into();
        let proof = proof.0;
        TranscriptGuard {
            transcript: self.transcript,
            proof,
        }
    }

    /// Allows to extract messages from the proof, absorbing them in the
    /// transcript automatically, also returning the corresponding challenges.
    pub fn receive_message<M, Q, const N: usize>(&mut self, query: Q) -> Result<(M, [F; N]), Error>
    where
        M: Message<F> + 'static,
        Q: Fn(&P) -> M,
    {
        let message = query(&self.proof);
        let challenges: [F; N] = self.transcript.send_message(&message)?;
        Ok((message, challenges))
    }
    /// similar to receive_message, doesn't interact with the sponge in any way and returns
    /// a guarded value to be unwrapped later.
    pub fn receive_message_delayed<M, Q>(&mut self, query: Q) -> MessageGuard<M>
    where
        M: 'static,
        Q: FnOnce(&P) -> M,
    {
        let message = query(&self.proof);
        MessageGuard(message)
    }
    /// unwraps the instance while absorbing it and also returning
    /// challenges.
    pub fn unwrap_guard<I: Message<F> + 'static, const N: usize>(
        &mut self,
        instance: MessageGuard<I>,
    ) -> Result<(I, [F; N]), Error> {
        let MessageGuard(instance) = instance;
        let challenges = self.transcript.send_message(&instance)?;
        Ok((instance, challenges))
    }
    /// Unwraps the instance while ignoring the transcript, caller must ensure
    /// that not including the instance is acceptable.
    /// Will still ultimately fail if the instance was expected in the pattern.
    pub fn unwrap_instance_unsafe<I>(&mut self, instance: MessageGuard<I>) -> I {
        instance.0
    }
    /// generates a multivariate point
    pub fn point(&mut self) -> Result<Vec<F>, Error> {
        self.transcript.point()
    }
}
