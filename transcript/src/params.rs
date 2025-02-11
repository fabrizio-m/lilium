use std::{
    any::{type_name, Any, TypeId},
    collections::BTreeMap,
};

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
        if self.map.contains_key(&id) {
            panic!("param already set: {}", type_name::<T>());
        } else {
            self.map.insert(id, value);
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
