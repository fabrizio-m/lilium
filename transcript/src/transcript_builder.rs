use crate::{
    messages::PointRound,
    params::ParamResolver,
    protocols::{Protocol, Reduction},
    Message, Transcript,
};
use ark_ff::Field;
use sponge::sponge::{Duplex, SpongeBuilder};
use std::{
    any::{Any, TypeId},
    marker::PhantomData,
};

pub struct TranscriptBuilder<F: Field> {
    rounds: Vec<(TypeId, usize)>,
    //TODO: can likely be handled through params
    vars: usize,
    // degree: usize,
    sponge_builder: SpongeBuilder,
    param_resolver: ParamResolver,
    _f: PhantomData<F>,
}

impl<F: Field> TranscriptBuilder<F> {
    pub fn add_protocol_patter<S: Protocol<F>>(self) -> Self {
        S::transcript_pattern(self)
    }
    pub fn add_reduction_patter<S: Reduction<F>>(self) -> Self {
        S::transcript_pattern(self)
    }
    pub fn new(vars: usize, params: ParamResolver) -> Self {
        let sponge_builder = SpongeBuilder::new();
        Self {
            rounds: vec![],
            vars,
            // degree,
            sponge_builder,
            param_resolver: params,
            _f: PhantomData,
        }
    }
    pub fn round<T: Any + Message<F>, const N: usize>(self) -> Self {
        let Self {
            mut rounds,
            sponge_builder,
            vars,
            // degree,
            param_resolver,
            ..
        } = self;
        let id = TypeId::of::<T>();
        rounds.push((id, N));

        let sponge_builder = sponge_builder
            .absorb(T::len(vars, &param_resolver).try_into().unwrap())
            .squeeze(N.try_into().unwrap());

        Self {
            rounds,
            sponge_builder,
            param_resolver,
            ..self
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
            ..self
        }
    }
    fn fold_round_rec<T: Any + Message<F>, const N: usize>(self, left: usize) -> Self {
        if left == 0 {
            self
        } else {
            let builder = self.round::<T, N>();
            builder.fold_round_rec::<T, N>(left - 1)
        }
    }
    /// Adds V rounds for the V variables in the transcript for split and fold
    /// protocols which send one message per variable.
    pub fn fold_rounds<T: Any + Message<F>, const N: usize>(self) -> Self {
        let vars = self.vars;
        self.fold_round_rec::<T, N>(vars)
    }
    pub fn finish<S: Duplex<F>>(self) -> TranscriptDescriptor<F, S> {
        let Self {
            rounds,
            sponge_builder,
            vars,
            ..
        } = self;
        let sponge = S::from_builder(sponge_builder);
        TranscriptDescriptor {
            sponge,
            rounds,
            vars,
        }
    }
    pub fn repeat<const N: usize, M: Fn(Self) -> Self>(self, f: M) -> Self {
        [(); N].iter().fold(self, |acc, _| f(acc))
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
        Transcript::new(sponge, rounds, self.vars)
    }
}
