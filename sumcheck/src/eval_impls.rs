use crate::polynomials::Evals;

impl<T: Evals<V> + Copy, V, const N: usize> Evals<V> for [T; N] {
    type Idx = (usize, T::Idx);

    fn index(&self, index: Self::Idx) -> &V {
        let (idx, inner_idx) = index;
        self[idx].index(inner_idx)
    }

    fn combine<C: Fn(V, V) -> V>(&self, other: &Self, f: C) -> Self {
        let mut res: [T; N] = self.clone();
        for i in 0..N {
            res[i] = self[i].combine(&other[i], &f);
        }
        res
    }

    fn flatten(self, vec: &mut Vec<V>) {
        for elem in self.into_iter() {
            elem.flatten(vec);
        }
    }

    fn unflatten(elems: &mut std::vec::IntoIter<V>) -> Self {
        [(); N].map(|_| T::unflatten(elems))
    }
}
