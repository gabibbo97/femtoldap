use crate::ldap::{attributes::LDAPAttributes, dn::LDAPDN, entry::LDAPEntry};

pub trait AsLDAPAttributes {
    /// Get the LDAP attributes for this entity
    fn as_ldap_attributes(&self) -> LDAPAttributes;
}

pub trait AugmentConfig {
    /// Get the LDAP DN of this entry
    fn as_ldap_dn(&self, _base_dn: &LDAPDN) -> Option<LDAPDN>;

    /// Transform self into an LDAP entry
    fn as_ldap_entry(&self, config: &super::Config, entries: &[LDAPEntry]) -> Option<LDAPEntry>;
}
