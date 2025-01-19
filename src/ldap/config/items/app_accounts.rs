use crate::ldap::{attributes::LDAPAttributes, config::traits::{AsLDAPAttributes, AugmentConfig}, entry::LDAPEntry, traits::Mergeable};

use super::{ExtraProperties, LoginProperties};

/// Inspired by RFC4524 - account
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AppAccount {
    /// Authentication data
    #[serde(flatten)] pub auth: LoginProperties,

    /// Description
    pub description: Option<String>,

    /// Extra properties
    #[serde(flatten)] pub extra_properties: ExtraProperties,

    /// Username
    pub uid: Option<String>,
}
impl AsLDAPAttributes for AppAccount {
    fn as_ldap_attributes(&self) -> LDAPAttributes {
        let mut attributes = LDAPAttributes::default();
        attributes.add_value(super::OBJECT_CLASS, "account");
        attributes.merge(self.auth.as_ldap_attributes());
        if let Some(description) = self.description.as_ref() {
            attributes.add_value("description", description);
        }
        attributes.merge(self.extra_properties.as_ldap_attributes());
        if let Some(uid) = self.uid.as_ref() {
            attributes.add_value("uid", uid);
        }
        attributes
    }
}
impl AugmentConfig for AppAccount {
    fn as_ldap_dn(&self, base_dn: &crate::ldap::dn::LDAPDN) -> Option<crate::ldap::dn::LDAPDN> {
        self.uid.as_ref()
            .map(|name|
                base_dn.clone()
                    .with_prefix("ou", "apps")
                    .with_prefix("uid", name)
                )
    }
    fn as_ldap_entry(&self, config: &crate::ldap::config::Config, _entries: &[LDAPEntry]) -> Option<LDAPEntry> {
        if self.uid.is_none() {
            tracing::warn!("Entry skipped: missing uid");
            return None;
        }
        let mut entry = LDAPEntry::new(self.as_ldap_dn(&config.base_dn)?, self.as_ldap_attributes());
        entry.acls.can_access_self = true;
        entry.acls.can_access_suffixes.push(
            config.base_dn.clone()
        );
        entry.acls.cant_access_suffixes.push(
            config.base_dn.clone()
                .with_prefix("ou", "apps")
        );
        Some(entry)
    }
}
impl Mergeable<Self> for AppAccount {
    fn merge(&mut self, other: Self) {
        self.auth.merge(other.auth);
        self.description.merge(other.description);
        self.extra_properties.merge(other.extra_properties);
        self.uid.merge(other.uid);
    }
}