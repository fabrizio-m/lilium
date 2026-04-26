use crate::batching::multipoint::{MultipointEvals, MultipointIdx};
use std::vec::IntoIter;
use sumcheck::polynomials::Evals;

impl<V: Copy> Evals<V> for MultipointEvals<V> {
    type Idx = MultipointIdx;

    fn index(&self, index: Self::Idx) -> &V {
        match index {
            MultipointIdx::Eq => &self.eq,
            MultipointIdx::Poly => &self.poly,
        }
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let eq = f(self.eq, other.eq);
        let poly = f(self.poly, other.poly);
        Self { eq, poly }
    }

    fn flatten(self, vec: &mut Vec<V>) {
        let Self { eq, poly } = self;
        vec.push(eq);
        vec.push(poly);
    }

    fn unflatten(elems: &mut IntoIter<V>) -> Self {
        let eq = elems.next().unwrap();
        let poly = elems.next().unwrap();
        Self { eq, poly }
    }
}
