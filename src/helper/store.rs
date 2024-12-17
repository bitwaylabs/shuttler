use std::{collections::BTreeMap, marker::PhantomData, path::Path};

use serde::{Deserialize, Serialize};
use sled::Db;

pub trait Store<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    fn save(&mut self, key: &K, value: &V) -> bool;
    fn list(&self) -> Vec<V>;
    fn remove(&mut self, key: &K) -> bool;
    fn get(&self, key: &K) -> Option<V>;
    fn exists(&self, key: &K) -> bool;
}

pub type DefaultStore<K, V> = SledStore<K, V>;

pub struct SledStore<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    inner: Db,
    _pdk: PhantomData<K>,
    _pdv: PhantomData<V>
}

impl<K, V> SledStore<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let inner = sled::open(path).unwrap();
        Self {
            inner,
            _pdk: PhantomData,
            _pdv: PhantomData,
        }
    }
}

impl<K, V> Store<K, V> for SledStore<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    fn save(&mut self, key: &K, value: &V) -> bool {
        let value = serde_json::to_vec(value).unwrap();
        self.inner
            .insert(key, value)
            .is_ok()
    }

    fn list(&self) -> Vec<V> {
        self.inner
        .iter()
        .map(|r| {
            let (_k, v) = r.unwrap();
            serde_json::from_slice(&v).unwrap()
        })
        .collect()
    }

    fn remove(&mut self, key: &K) -> bool {
        self.inner.remove(key).is_ok()
    }

    fn get(&self, key: &K) -> Option<V> {
        match self.inner.get(key) {
            Ok(Some(v)) => Some(serde_json::from_slice(&v).unwrap()),
            _ => None,
        }
    }

    fn exists(&self, key: &K) -> bool {
        self.inner.contains_key(key).unwrap_or(false)
    }
}

pub struct MemStore<K, V> where K: AsRef<[u8]> + Ord + Clone, V: Serialize + for<'a> Deserialize<'a> + Clone {
    inner: BTreeMap<K, V>,
}


impl<K, V> MemStore<K, V> where K: AsRef<[u8]> + Ord + Clone, V: Serialize + for<'a> Deserialize<'a> + Clone {
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new()
        }
    }
}

impl<K, V> Store<K, V> for MemStore<K, V> where K: AsRef<[u8]> + Ord + Clone, V: Serialize + for<'a> Deserialize<'a> + Clone {
    fn save(&mut self, key: &K, value: &V) -> bool {
        self.inner.insert(key.clone(), value.clone()).is_some()
    }

    fn list(&self) -> Vec<V> {
        self.inner.values().map(|v| v.clone()).collect::<Vec<_>>()
    }

    fn remove(&mut self, key: &K) -> bool {
        self.inner.remove(key).is_some()
    }

    fn get(&self, key: &K) -> Option<V> {
        self.inner.get(key).map(|v| v.clone())
    }

    fn exists(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }
}