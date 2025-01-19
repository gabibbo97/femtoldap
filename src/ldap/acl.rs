use super::{dn::LDAPDN, entry::LDAPEntry, traits::Mergeable};

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct LDAPACL {
    pub can_access_self: bool,
    #[serde(default)] pub can_access_suffixes: Vec<LDAPDN>, // TODO - ACL simplifier
    #[serde(default)] pub cant_access_suffixes: Vec<LDAPDN>, // TODO - ACL simplifier
}
impl LDAPACL {

    pub fn can_access_dn(&self, entry: &LDAPEntry, target_dn: &LDAPDN) -> bool {
        if self.can_access_self && (&entry.dn == target_dn) {
            true
        } else if self.can_access_suffixes.iter().any(|suffix| target_dn.matches_suffix(suffix)) && !self.cant_access_suffixes.iter().any(|suffix| target_dn.matches_suffix(suffix)) {
            true
        } else {
            false
        }
    }

    pub fn tidy(&mut self) {
        self.can_access_suffixes.shrink_to_fit();
        self.cant_access_suffixes.shrink_to_fit();
    }

}
impl Mergeable<Self> for LDAPACL {
    fn merge(&mut self, other: Self) {
        self.can_access_self.merge(other.can_access_self);
        self.can_access_suffixes.merge(other.can_access_suffixes);
        self.cant_access_suffixes.merge(other.cant_access_suffixes);
    }
}
