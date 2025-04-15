use std::{collections::BTreeMap, fmt::Debug};

/// Provides unique and sequential ids for an arbitrary key K.
pub struct IdMap<K> {
    ids: BTreeMap<K, usize>,
    next_id: usize,
}

impl<K> IdMap<K>
where
    K: Copy + Ord + Debug,
{
    pub fn new() -> Self {
        Self {
            ids: BTreeMap::new(),
            next_id: 0,
        }
    }

    pub fn get_id(&mut self, key: K) -> usize {
        *self.ids.entry(key).or_insert_with(|| {
            let id = self.next_id;
            self.next_id += 1;
            id
        })
    }

    /// Consume and create a (usize -> K) map with the usize implicit
    /// on the index.
    pub fn finish(self) -> Vec<K> {
        let Self { ids, .. } = self;
        let len = ids.len();
        let mut map = Vec::with_capacity(len);
        let mut ids_inverted: Vec<(usize, K)> = ids.into_iter().map(|(a, b)| (b, a)).collect();
        ids_inverted.sort_by_key(|(x, _)| *x);
        let ids = ids_inverted.into_iter();
        for (i1, (i2, k)) in ids.enumerate() {
            assert_eq!(i1, i2);
            map.push(k);
        }
        map
    }
}
