use std::fmt::Write;

use super::traits::Mergeable;

#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct LDAPAttribute {
    pub name: String,
    pub values: Vec<Vec<u8>>,
}
impl LDAPAttribute {

    pub fn new_single(name: impl Into<String>, value: impl AsRef<[u8]>) -> Self {
        Self::new_multiple(name, &[value])
    }

    pub fn new_multiple(name: impl Into<String>, values: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self {
        Self {
            name: name.into(),
            values: values.into_iter()
                .map(|x| x.as_ref().to_vec())
                .collect()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn as_ldap3_protocol_attribute(&self) -> ldap3_proto::LdapPartialAttribute {
        ldap3_proto::LdapPartialAttribute { atype: self.name.clone(), vals: self.values.clone() }
    }

    pub fn tidy(&mut self) {
        self.values.shrink_to_fit();
    }

}
impl std::fmt::Debug for LDAPAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)?;
        f.write_str(" = [")?;
        for (i, value) in self.values.iter().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            if let Ok(s) = std::str::from_utf8(&value) {
                s.fmt(f)?;
            } else {
                value.fmt(f)?;
            }
        }
        f.write_char(']')?;
        Ok(())
    }
}
impl Mergeable<Self> for LDAPAttribute {
    fn merge(&mut self, other: Self) {
        assert_eq!(self.name, other.name);
        self.values.merge(other.values);
    }
}
