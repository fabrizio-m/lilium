use ark_ff::Field;
use std::ops::Index;
use sumcheck::{
    polynomials::Evals,
    sumcheck::{Env, SumcheckFunction, Var},
};

pub mod eq;
pub mod mvlookup;
