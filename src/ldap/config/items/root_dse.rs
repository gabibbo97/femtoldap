use crate::ldap::{attributes::LDAPAttributes, config::{traits::AugmentConfig, Config}, dn::LDAPDN, entry::LDAPEntry};

#[derive(Default)]
pub struct RootDSE;
impl AugmentConfig for RootDSE {
    fn as_ldap_dn(&self, _base_dn: &LDAPDN) -> Option<LDAPDN> {
        Some(LDAPDN::empty())
    }
    fn as_ldap_entry(&self, config: &Config, _entries: &[LDAPEntry]) -> Option<LDAPEntry> {
        let mut entry = LDAPEntry::new(LDAPDN::empty(), LDAPAttributes::default());
        entry.attributes.add_value(super::OBJECT_CLASS, "femtoLDAPRoot");
        entry.attributes.add_value(super::OBJECT_CLASS, "extensibleObject");
        entry.attributes.add_value("dsaName", "femtoLDAP");
        entry.attributes.add_value("namingContexts", config.base_dn.to_string());
        entry.attributes.add_value("supportedAuthPasswordSchemes", "CLEAR");
        entry.attributes.add_value("supportedLDAPVersion", "3");
        entry.attributes.add_value("vendorName", "femtoldap");
        entry.attributes.add_value("vendorVersion", "whatever");
        entry.attributes.add_value("entryDN", "");
        entry.attributes.add_value("entryUUID", uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_X500, &[]).hyphenated().to_string());
        Some(entry)
    }
}
