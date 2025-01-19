use crate::ldap::{attributes::LDAPAttributes, config::traits::{AsLDAPAttributes, AugmentConfig}, datatypes::CIString, dn::LDAPDN, entry::LDAPEntry, traits::Mergeable};

use super::ExtraProperties;

/// Inspired by RFC4519 - groupOfUniqueNames
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Group {
    /// Description
    pub description: Option<String>,

    /// Extra properties
    #[serde(flatten)] pub extra_properties: ExtraProperties,

    /// Name
    pub name: Option<String>,
}
impl AsLDAPAttributes for Group {
    fn as_ldap_attributes(&self) -> LDAPAttributes {
        let mut attributes = LDAPAttributes::default();
        attributes.add_value(super::OBJECT_CLASS, "groupOfUniqueNames");
        if let Some(description) = self.description.as_ref() {
            attributes.add_value("description", description);
        }
        attributes.merge(self.extra_properties.as_ldap_attributes());
        if let Some(name) = self.name.as_ref() {
            attributes.add_value("cn", name);
        }
        attributes
    }
}
impl AugmentConfig for Group {
    fn as_ldap_dn(&self, base_dn: &LDAPDN) -> Option<crate::ldap::dn::LDAPDN> {
        self.name.as_ref()
            .map(|name|
                base_dn.clone()
                    .with_prefix("ou", "groups")
                    .with_prefix("cn", name)
                )
    }
    fn as_ldap_entry(&self, config: &crate::ldap::config::Config, _entries: &[crate::ldap::entry::LDAPEntry]) -> Option<crate::ldap::entry::LDAPEntry> {
        if self.name.is_none() {
            tracing::warn!("Entry skipped: missing name");
            return None;
        }
        let mut entry = LDAPEntry::new(self.as_ldap_dn(&config.base_dn)?, self.as_ldap_attributes());

        // uniqueMember
        let group_name = self.name.as_ref().unwrap();
        for user in config.data.users.iter() {
            if user.group_names.contains(group_name) {
                if let Some(dn) = user.as_ldap_dn(&config.base_dn) {
                    entry.attributes.add_value("uniqueMember", dn.to_string());
                } else {
                    tracing::warn!(?user, "Empty DN");
                }
            }
        }

        if entry.attributes.has_attribute(&CIString::new("uniqueMember")) {
            Some(entry)
        } else {
            None
        }
    }
}
impl Mergeable<Self> for Group {
    fn merge(&mut self, other: Self) {
        self.description.merge(other.description);
        self.extra_properties.merge(other.extra_properties);
        self.name.merge(other.name);
    }
}