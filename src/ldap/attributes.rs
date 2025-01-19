use std::collections::HashMap;

use super::{attribute::LDAPAttribute, datatypes::CIString, traits::Mergeable};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct LDAPAttributes {
    attributes: HashMap<CIString, LDAPAttribute>,
}
impl LDAPAttributes {

    pub fn add_attribute(&mut self, attribute: LDAPAttribute) {
        self.attributes.merge((CIString::new(&attribute.name), attribute));
    }

    pub fn add_value(&mut self, k: impl AsRef<str>, v: impl AsRef<[u8]>) {
        self.add_attribute(LDAPAttribute::new_single(k.as_ref(), v));
    }

    pub fn add_value_if_absent(&mut self, k: impl AsRef<str>, v: impl AsRef<[u8]>) {
        if let Some(attribute) = self.get_attribute(&CIString::new(k.as_ref())) {
            if ! attribute.values.iter().any(|x| x == v.as_ref()) {
                self.add_attribute(LDAPAttribute::new_single(k.as_ref(), v));
            }
        } else {
            self.add_attribute(LDAPAttribute::new_single(k.as_ref(), v));
        }
    }

    pub fn check_password(&self, password: impl AsRef<str>) -> bool {
        if let Some(attribute) = self.get_attribute(&CIString::new("userPassword")) {
            attribute.values.iter()
                .any(|accepted_password| accepted_password == password.as_ref().as_bytes())
        } else {
            false
        }
    }

    pub fn has_attribute(&self, k: &CIString) -> bool {
        self.get_attribute(k).is_some()
    }

    pub fn get_attribute(&self, k: &CIString) -> Option<&LDAPAttribute> {
        self.attributes.get(k)
    }

    pub fn iter(&self) -> impl Iterator<Item = &LDAPAttribute> {
        self.attributes.values()
    }

    pub fn tidy(&mut self) {
        // delete empty attributes
        self.attributes.retain(|_, v| !v.is_empty());

        // shrink attributes
        self.attributes.values_mut().for_each(|x| x.tidy());
        self.attributes.shrink_to_fit();
    }

}
impl<I: AsRef<str>> std::ops::Index<I> for LDAPAttributes {
    type Output = LDAPAttribute;
    fn index(&self, index: I) -> &Self::Output {
        self.attributes.get(&CIString::new(index)).unwrap()
    }
}
impl<I: AsRef<str>> std::ops::IndexMut<I> for LDAPAttributes {
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.attributes.get_mut(&CIString::new(index)).unwrap()
    }
}
impl std::fmt::Debug for LDAPAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("{ ")?;
        for (i, attribute) in self.attributes.values().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            attribute.fmt(f)?;
        }
        f.write_str(" }")?;
        Ok(())
    }
}
impl Mergeable<Self> for LDAPAttributes {
    fn merge(&mut self, other: Self) {
        self.attributes.merge(other.attributes);
    }
}
