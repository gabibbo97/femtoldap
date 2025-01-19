use serde_with::{formats::PreferOne, OneOrMany};
use std::collections::HashSet;

use crate::ldap::{attributes::LDAPAttributes, config::traits::{AsLDAPAttributes, AugmentConfig}, entry::LDAPEntry, traits::Mergeable};

use super::{ExtraProperties, LoginProperties};

#[serde_with::serde_as]
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct User {
    /// Authentication data
    #[serde(flatten)] pub auth: LoginProperties,

    /// Extra properties
    #[serde(flatten)] pub extra_properties: ExtraProperties,

    /// User id (username)
    pub uid: Option<String>,

    /// User name
    #[serde(default)] #[serde_as(as = "OneOrMany<_, PreferOne>")] pub name: Vec<String>,
    /// User surname
    #[serde(default)] #[serde_as(as = "OneOrMany<_, PreferOne>")] pub surname: Vec<String>,
    /// User display name
    pub display_name: Option<String>,

    /// User initials
    pub initials: Option<String>,

    /// User preferred language
    pub preferred_language: Option<String>,

    /// User mobile number
    #[serde(default)] #[serde_as(as = "OneOrMany<_, PreferOne>")] pub mobile_number: Vec<String>,
    /// User telephone number
    #[serde(default)] #[serde_as(as = "OneOrMany<_, PreferOne>")] pub telephone_number: Vec<String>,

    /// User primary email
    pub mail: Option<String>,

    /// User SSH public keys
    #[serde(default)] pub ssh_public_key: HashSet<String>,

    /// User login shell
    pub login_shell: Option<String>,
    /// User home directory
    pub home_directory: Option<String>,
    /// User posix uid number
    pub uid_number: Option<String>,
    /// User posix gid number
    pub gid_number: Option<String>,

    //
    // Properties used for generating entries
    //
    /// Group names to which the user belongs
    #[serde(default, alias = "groups")] pub group_names: HashSet<String>,
    /// Additional mail aliases for the user
    #[serde(default)] pub mail_aliases: HashSet<String>,
}
impl AsLDAPAttributes for User {
    fn as_ldap_attributes(&self) -> LDAPAttributes {
        let mut attributes = LDAPAttributes::default();
        attributes.merge(self.auth.as_ldap_attributes());
        attributes.merge(self.extra_properties.as_ldap_attributes());

        attributes.add_value(super::OBJECT_CLASS, "inetOrgPerson");

        if let Some(uid) = self.uid.as_ref() {
            attributes.add_value("uid", uid);
        }

        for name in self.name.iter() {
            attributes.add_value("givenName", name);
        }
        for surname in self.surname.iter() {
            attributes.add_value("sn", surname);
        }
        if let Some(display_name) = self.display_name.as_ref() {
            attributes.add_value("displayName", display_name);
        } else if !self.name.is_empty() && !self.surname.is_empty() {
            attributes.add_value("displayName", self.name.iter().chain(self.surname.iter()).map(|x| x.as_str()).collect::<Vec<_>>().join(" "));
        }

        if let Some(preferred_language) = self.preferred_language.as_ref() {
            attributes.add_value("preferredLanguage", preferred_language);
        }

        for mobile in self.mobile_number.iter() {
            attributes.add_value("mobile", mobile);
        }
        for telephone in self.telephone_number.iter() {
            attributes.add_value("telephoneNumber", telephone);
        }

        if let Some(mail) = self.mail.as_ref() {
            attributes.add_value("mail", mail);
        }
        for mail in self.mail_aliases.iter() {
            attributes.add_value("mailAlias", mail);
        }

        for key in self.ssh_public_key.iter() {
            attributes.add_value("sshPublicKey", key);
        }

        if let Some(home_directory) = self.home_directory.as_ref() {
            attributes.add_value_if_absent(super::OBJECT_CLASS, "posixAccount");
            attributes.add_value("homeDirectory", home_directory);
        } else if let Some(uid) = self.uid.as_ref() {
            attributes.add_value_if_absent(super::OBJECT_CLASS, "posixAccount");
            attributes.add_value("homeDirectory", format!("/home/{uid}"));
        }
        if let Some(login_shell) = self.login_shell.as_ref() {
            attributes.add_value_if_absent(super::OBJECT_CLASS, "posixAccount");
            attributes.add_value("loginShell", login_shell);
        }
        if let Some(uid_number) = self.uid_number.as_ref() {
            attributes.add_value_if_absent(super::OBJECT_CLASS, "posixAccount");
            attributes.add_value("uidNumber", uid_number);
        }
        if let Some(gid_number) = self.gid_number.as_ref() {
            attributes.add_value_if_absent(super::OBJECT_CLASS, "posixAccount");
            attributes.add_value("gidNumber", gid_number);
        }

        attributes
    }
}
impl AugmentConfig for User {
    fn as_ldap_dn(&self, base_dn: &crate::ldap::dn::LDAPDN) -> Option<crate::ldap::dn::LDAPDN> {
        self.uid.as_ref()
            .map(|name|
                base_dn.clone()
                    .with_prefix("ou", "users")
                    .with_prefix("uid", name)
                )
    }
    fn as_ldap_entry(&self, config: &crate::ldap::config::Config, _entries: &[crate::ldap::entry::LDAPEntry]) -> Option<crate::ldap::entry::LDAPEntry> {
        //
        // Checks
        //
        if self.uid.is_none() {
            tracing::warn!("Entry skipped: missing uid");
            return None;
        }
        //
        // Assemble entry
        //
        let mut entry = LDAPEntry::new(self.as_ldap_dn(&config.base_dn)?, self.as_ldap_attributes());
        entry.acls.can_access_self = true;

        // memberOf
        for group_name in self.group_names.iter() {
            if let Some(group) = config.data.groups.iter().find(|group| group.name.as_ref().map(|name| name == group_name).unwrap_or(false)) {
                if let Some(dn) = group.as_ldap_dn(&config.base_dn) {
                    entry.attributes.add_value("memberOf", dn.to_string());
                } else {
                    tracing::warn!(group_name, "Empty DN");
                }
            } else {
                tracing::warn!(group_name, "Group not found");
            }
        }

        Some(entry)
    }
}
impl Mergeable<Self> for User {
    fn merge(&mut self, other: Self) {
        self.auth.merge(other.auth);
        self.extra_properties.merge(other.extra_properties);
        self.uid.merge(other.uid);
        self.name.merge(other.name);
        self.surname.merge(other.surname);
        self.display_name.merge(other.display_name);
        self.initials.merge(other.initials);
        self.preferred_language.merge(other.preferred_language);
        self.mobile_number.merge(other.mobile_number);
        self.telephone_number.merge(other.telephone_number);
        self.mail.merge(other.mail);
        self.ssh_public_key.merge(other.ssh_public_key);
        self.login_shell.merge(other.login_shell);
        self.home_directory.merge(other.home_directory);
        self.uid_number.merge(other.uid_number);
        self.gid_number.merge(other.gid_number);
    }
}
