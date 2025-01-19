use items::{AppAccount, Group, MailAlias, RootDSE, User};
use traits::AugmentConfig;

use super::{datatypes::CIString, dn::LDAPDN, entry::LDAPEntry, traits::Mergeable};

pub mod items;
pub mod traits;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Config {
    /// The base DN for all entities
    pub base_dn: LDAPDN,

    /// The actual contents of the directory
    #[serde(flatten)]
    pub data: DirectoryContents,
}
impl Config {
    pub fn assemble_entries(&self) -> Vec<LDAPEntry> {
        // prepare config and entires
        let config = self.clone();
        let mut entries = Vec::new();

        // root DSE
        entries.push(RootDSE::default().as_ldap_entry(&config, &entries).unwrap());

        // applications
        for application in config.data.apps.iter() {
            if let Some(entry) = application.as_ldap_entry(&config, &entries) {
                entries.push(entry);
            }
        }

        // groups
        for group in config.data.groups.iter() {
            if let Some(entry) = group.as_ldap_entry(&config, &entries) {
                entries.push(entry);
            }
        }

        // mail aliases
        for mail_alias in config.data.mail_aliases.iter() {
            if let Some(entry) = mail_alias.as_ldap_entry(&config, &entries) {
                entries.push(entry);
            }
        }

        // users
        for user in config.data.users.iter() {
            if let Some(entry) = user.as_ldap_entry(&config, &entries) {
                entries.push(entry);
            }
        }

        // add entryDN operational attribute
        entries
            .iter_mut()
            .filter(|entry| !entry.dn.is_empty())
            .filter(|entry| !entry.attributes.has_attribute(&CIString::new("entryDN")))
            .for_each(|entry| entry.attributes.add_value("entryDN", entry.dn.to_string()));

        // add entryUUID operational attribute
        entries
            .iter_mut()
            .filter(|entry| !entry.dn.is_empty())
            .filter(|entry| !entry.attributes.has_attribute(&CIString::new("entryUUID")))
            .for_each(|entry| {
                entry
                    .attributes
                    .add_value("entryUUID", entry.dn.uuid().as_hyphenated().to_string())
            });

        entries
    }
}
impl Mergeable<Self> for Config {
    fn merge(&mut self, other: Self) {
        self.base_dn.merge(other.base_dn);
        self.data.merge(other.data);
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DirectoryContents {
    #[serde(default)]
    pub apps: Vec<AppAccount>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub mail_aliases: Vec<MailAlias>,
    #[serde(default)]
    pub users: Vec<User>,
}
impl DirectoryContents {
    #[tracing::instrument(skip_all)]
    fn merge_to_entity_with_same_dn_or_add<T: AugmentConfig + Mergeable<T> + std::fmt::Debug>(
        search_entity: T,
        search_domain: &mut Vec<T>,
    ) {
        let base_dn = LDAPDN::empty();
        if let Some(search_dn) = search_entity.as_ldap_dn(&base_dn) {
            match search_domain.iter_mut().find(|entity| {
                entity
                    .as_ldap_dn(&base_dn)
                    .map(|entity_dn| entity_dn == search_dn)
                    .unwrap_or(false)
            }) {
                Some(entity) => {
                    tracing::debug!(?entity, ?search_entity, "Merging");
                    entity.merge(search_entity)
                },
                None => {
                    tracing::debug!(?search_entity, "Adding new");
                    search_domain.push(search_entity)
                },
            }
        } else {
            tracing::warn!(?search_entity, "Could not create entity DN");
        }
    }
}
impl Mergeable<Self> for DirectoryContents {
    fn merge(&mut self, mut other: Self) {
        other.apps.drain(..).for_each(|app| Self::merge_to_entity_with_same_dn_or_add(app, &mut self.apps));
        other.groups.drain(..).for_each(|group| Self::merge_to_entity_with_same_dn_or_add(group, &mut self.groups));
        other.mail_aliases.drain(..).for_each(|mail_alias| Self::merge_to_entity_with_same_dn_or_add(mail_alias, &mut self.mail_aliases));
        other.users.drain(..).for_each(|user| Self::merge_to_entity_with_same_dn_or_add(user, &mut self.users));
    }
}
