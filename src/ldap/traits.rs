use std::collections::{HashMap, HashSet, VecDeque};

pub trait Mergeable<W> {
    fn merge(&mut self, other: W);
}

impl Mergeable<Self> for bool {
    fn merge(&mut self, other: Self) {
        *self |= other;
    }
}

impl Mergeable<Self> for String {
    fn merge(&mut self, other: Self) {
        if self.is_empty() && !other.is_empty() {
            let _ = std::mem::replace(self, other);
        }
    }
}

impl<T> Mergeable<Self> for Option<T> {
    fn merge(&mut self, other: Self) {
        if self.is_none() && other.is_some() {
            let _ = std::mem::replace(self, other);
        }
    }
}

impl<T> Mergeable<Self> for HashSet<T>
where
    T: Eq + std::hash::Hash
{
    fn merge(&mut self, mut other: Self) {
        self.extend(other.drain());
    }
}
impl<T> Mergeable<T> for HashSet<T>
where
    T: Eq + std::hash::Hash
{
    fn merge(&mut self, other: T) {
        self.insert(other);
    }
}

impl<T> Mergeable<Self> for Vec<T>
where
    T: Eq
{
    fn merge(&mut self, other: Self) {
        for entry in other {
            if ! self.contains(&entry) {
                self.push(entry);
            }
        }
    }
}
impl<T> Mergeable<Self> for VecDeque<T>
where
    T: Eq
{
    fn merge(&mut self, other: Self) {
        for entry in other {
            if ! self.contains(&entry) {
                self.push_back(entry);
            }
        }
    }
}

impl<K,V> Mergeable<Self> for HashMap<K,V>
where
    K: Eq + std::hash::Hash,
    V: Mergeable<V>
{
    fn merge(&mut self, mut other: Self) {
        for (k, v) in other.drain() {
            match self.entry(k) {
                std::collections::hash_map::Entry::Occupied(mut occupied_entry) => occupied_entry.get_mut().merge(v),
                std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(v);
                },
            }
        }
    }
}
impl<K,V> Mergeable<(K, V)> for HashMap<K,V>
where
    K: Eq + std::hash::Hash,
    V: Eq + std::hash::Hash + Mergeable<V>,
{
    fn merge(&mut self, other: (K, V)) {
        self.merge(HashMap::from([other]));
    }
}
