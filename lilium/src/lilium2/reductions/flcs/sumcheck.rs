use crate::lilium2::oracles::MatrixNature;
use ark_ff::Field;
use ccs::structure::Exp;
use commit::commit2::oracle::CommittedNature;
use std::{fmt::Debug, vec::IntoIter};
use sumcheck::{
    sumcheck::Var,
    sumcheck2::{
        evals::{Evals, EvalsCore},
        oracles::{
            composite::Either,
            core::{Coeffs, CoreNature},
            SumcheckFunction,
        },
    },
};
use sumcheck_derive::EvalsCore;

#[derive(Clone, Copy, Debug, EvalsCore)]
#[allow(dead_code)]
pub struct FlcsEvals<V: Debug + Clone, const IO: usize, const S: usize> {
    /// matrix vector products M(x)z(x)
    products: [V; IO],
    w: V,
    inputs: V,
    input_selector: V,
    gate_selectors: [V; S],
    constants: V,
    /// Constraint combination challenge.
    challenge: V,
}

type Natures = Either<CommittedNature, Either<CoreNature, MatrixNature>>;

#[derive(Clone, Debug)]
pub struct FlcsData {
    gates: Vec<Vec<Exp<usize>>>,
    multi_constraint: bool,
    // inputs: usize,
}

impl<F: Field, const IO: usize, const S: usize> SumcheckFunction<F> for FlcsEvals<(), IO, S> {
    type Natures = Natures;

    type Data = FlcsData;

    fn natures() -> Self::Mles<Self::Natures> {
        use Either::*;

        let products = [Right(Right(MatrixNature)); IO];
        let w = Left(CommittedNature::Witness);
        //TODO:
        let inputs = Right(Left(CoreNature::SmallInstance(Coeffs::Fixed(3))));
        let input_selector = Right(Left(CoreNature::SmallStructure));
        let gate_selectors = [Left(CommittedNature::Structure); S];
        let constants = Left(CommittedNature::Structure);
        let challenge = Right(Left(CoreNature::Challenge));

        FlcsEvals {
            products,
            w,
            inputs,
            input_selector,
            gate_selectors,
            constants,
            challenge,
        }
    }

    fn function<V: Var<F> + Debug>(data: &Self::Data, evals: &Self::Mles<V>) -> V {
        let FlcsEvals {
            products,
            w,
            inputs,
            input_selector,
            gate_selectors,
            constants,
            challenge,
        } = evals;

        let inputs_check = { input_selector.clone() - inputs.clone() * w };

        let mut acc = inputs_check;

        for (i, constraints) in data.gates.iter().enumerate() {
            let selector = &gate_selectors[i];

            for constraint in constraints {
                let exp = if matches!(constraint, Exp::Constant) {
                    let product = products[0].clone();
                    product - constants
                } else {
                    let exp = constraint;
                    eval_exp(evals, exp)
                };
                acc = if data.multi_constraint {
                    acc * challenge + exp * selector
                } else {
                    acc + exp * selector
                };
            }
        }

        todo!()
    }
}

fn eval_exp<F, V, const IO: usize, const S: usize>(
    evals: &FlcsEvals<V, IO, S>,
    exp: &Exp<usize>,
) -> V
where
    F: Field,
    V: Var<F> + Debug,
{
    match exp {
        Exp::Atom(i) => evals.products[*i].clone(),
        Exp::Add(e1, e2) => eval_exp(evals, e1) + eval_exp(evals, e2),
        Exp::Mul(e1, e2) => eval_exp(evals, e1) * eval_exp(evals, e2),
        Exp::Sub(e1, e2) => eval_exp(evals, e1) - eval_exp(evals, e2),
        Exp::Constant => evals.constants.clone(),
    }
}
