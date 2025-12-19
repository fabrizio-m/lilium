use std::{
    any::{type_name, Any, TypeId},
    collections::{btree_map::Entry, BTreeMap},
};

#[derive(Default, Debug)]
pub struct ParamResolver {
    map: BTreeMap<TypeId, usize>,
}

impl ParamResolver {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Sets the given param to the given value, trying to a set second value
    /// for the same type will panic.
    pub fn set<T: Any>(&mut self, value: usize) {
        let id = TypeId::of::<T>();
        match self.map.entry(id) {
            Entry::Vacant(e) => {
                e.insert(value);
            }
            Entry::Occupied(e) => {
                if &value != e.get() {
                    panic!(
                        "Tried to set param {} to {} when {} was already set",
                        type_name::<T>(),
                        value,
                        e.get()
                    );
                }
            }
        }
    }

    pub fn get<T: Any>(&self) -> usize {
        let id = TypeId::of::<T>();
        match self.map.get(&id) {
            Some(value) => *value,
            None => {
                panic!("param not present: {}", type_name::<T>());
            }
        }
    }
}
