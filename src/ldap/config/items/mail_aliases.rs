use std::collections::HashSet;

use crate::ldap::{attributes::LDAPAttributes, config::traits::{AsLDAPAttributes, AugmentConfig}, entry::LDAPEntry, traits::Mergeable};

use super::ExtraProperties;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MailAlias {
    /// Aliases
    #[serde(default, skip_serializing_if = "HashSet::is_empty")] pub aliases: HashSet<String>,

    /// Destination mail
    pub mail: Option<String>,

    /// Additional properties
    #[serde(flatten)] pub extra_properties: ExtraProperties,
}
impl AsLDAPAttributes for MailAlias {
    fn as_ldap_attributes(&self) -> LDAPAttributes {
        let mut attributes = LDAPAttributes::default();
        attributes.add_value(super::OBJECT_CLASS, "nisMailAlias");
        if let Some(mail) = &self.mail {
            attributes.add_value("cn", mail);
        }
        for alias in &self.aliases {
            attributes.add_value("rfc822mailMember", alias);
        }
        attributes.merge(self.extra_properties.as_ldap_attributes());
        attributes
    }
}
impl AugmentConfig for MailAlias {

    fn as_ldap_dn(&self, base_dn: &crate::ldap::dn::LDAPDN) -> Option<crate::ldap::dn::LDAPDN> {
        self.mail.as_ref()
            .map(|name|
                base_dn.clone()
                    .with_prefix("ou", "mail")
                    .with_prefix("ou", "aliases")
                    .with_prefix("cn", name)
                )
    }

    #[tracing::instrument(skip(config, _entries))]
    fn as_ldap_entry(&self, config: &crate::ldap::config::Config, _entries: &[LDAPEntry]) -> Option<LDAPEntry> {
        if self.mail.is_none() {
            tracing::warn!("Entry skipped: missing email");
            return None;
        }
        let mail = self.mail.as_ref().unwrap();
        let mut entry = LDAPEntry::new(self.as_ldap_dn(&config.base_dn)?, self.as_ldap_attributes());

        // aliases for users
        for user in config.data.users.iter() {
            if user.mail_aliases.contains(mail) {
                if let Some(user_mail) = user.mail.as_ref() {
                    entry.attributes.add_value("rfc822mailMember", user_mail);
                } else {
                    tracing::warn!(?user, "No mail address specified");
                }
            }
        }

        Some(entry)
    }
}
impl Mergeable<Self> for MailAlias {
    fn merge(&mut self, other: Self) {
        self.aliases.merge(other.aliases);
        self.mail.merge(other.mail);
        self.extra_properties.merge(other.extra_properties);
    }
}