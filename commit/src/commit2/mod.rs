use ark_ff::Field;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, Mul};
use sumcheck::polynomials::{EvalsExt, MultiPoint, SingleEval};
use sumcheck::sumcheck2::oracles::UnexpectedVars;
use transcript::reduction2::{Argument, Message, NoError, Relation};

pub trait CommitmentSchemeCore<F: Field>: Clone + Debug + 'static {
    type Commitment: for<'a> Add<&'a Self::Commitment, Output = Self::Commitment>
        + Add<Output = Self::Commitment>
        + Mul<F, Output = Self::Commitment>
        + Eq
        + Clone
        + Debug
        + Message<F, Params = (), Error = NoError>;

    fn new(vars: usize) -> Self;

    fn commit_mle(&self, evals: &[F]) -> Self::Commitment;

    fn commit_small_set(&self, evals: &[u8], set: [F; 256]) -> Self::Commitment {
        let evals: Vec<F> = evals.iter().map(|i| set[*i as usize]).collect();
        self.commit_mle(evals.as_slice())
    }
    /// Further specialized version of [Self::commit_small_set], where the set is
    /// [0..256].
    fn commit_bytes(&self, evals: &[u8]) -> Self::Commitment {
        let set: Vec<F> = (0..256).map(|i| F::from(i as u8)).collect();
        let set: [F; 256] = set.try_into().unwrap();
        self.commit_small_set(evals, set)
    }
}

/// For structure pcs.
/// For multilineal polynomial P, point x and eval y.
/// And for commitment C.
/// (pcs,(C,x,y),P) is in the relation if:
/// P(x) = y
/// And:
/// C = pcs(P)
pub struct OpeningRelation<F, C>(PhantomData<(F, C)>);

#[derive(Debug, Clone)]
pub struct OpenInstance<F: Field, C: CommitmentSchemeCore<F>> {
    pub commit: C::Commitment,
    pub point: MultiPoint<F>,
    pub eval: F,
}

impl<F: Field, C: CommitmentSchemeCore<F>> Message<F> for OpenInstance<F, C> {
    type Params = usize;

    type Error = UnexpectedVars;

    fn len(params: &Self::Params) -> usize {
        C::Commitment::len(&()) + MultiPoint::<F>::len(params) + 1
    }

    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error> {
        let Ok(mut elems) = self.commit.to_field_elements(expected_len);
        let elems_len = elems.len();
        elems.extend(self.point.to_field_elements(expected_len - elems_len - 1)?);
        elems.push(self.eval);
        Ok(elems)
    }
}

impl<F: Field, C: CommitmentSchemeCore<F>> Relation for OpeningRelation<F, C> {
    type Structure = C;

    type Instance = OpenInstance<F, C>;

    // NOTE: It may be of interest to add a randomness in the future, having
    // (Vec<F>, F) instead.
    type Witness = Vec<F>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let OpenInstance {
            commit,
            point,
            eval,
        } = instance;
        assert_eq!(witness.len(), 1 << point.vars());

        let expected_eval =
            EvalsExt::eval_iter(witness.iter().cloned().map(SingleEval), point.clone());

        if expected_eval.0 != *eval {
            return false;
        }

        let expected_commit = structure.commit_mle(witness);

        expected_commit == commit.clone()
    }
}

pub trait CommitmentScheme<F: Field>:
    CommitmentSchemeCore<F> + Argument<F, OpeningRelation<F, Self>>
{
}
