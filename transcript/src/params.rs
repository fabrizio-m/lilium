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

    pub fn set<T: Any>(&mut self, value: usize) {
        let id = TypeId::of::<T>();
        if let Entry::Vacant(e) = self.map.entry(id) {
            e.insert(value);
        } else {
            panic!("param already set: {}", type_name::<T>());
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
