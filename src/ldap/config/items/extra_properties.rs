use std::collections::{HashMap, HashSet};

use crate::ldap::{attributes::LDAPAttributes, config::traits::AsLDAPAttributes, traits::Mergeable};

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExtraProperties {
    /// Force a different UUID for the entity
    pub uuid: Option<uuid::Uuid>,

    /// Add arbitrary attributes to the entity
    #[serde(flatten)] pub extra_attributes: HashMap<String,Vec<String>>,

    /// Add arbitrary object classes to the entity
    #[serde(default, skip_serializing_if = "HashSet::is_empty")] pub extra_object_classes: HashSet<String>,
}
impl AsLDAPAttributes for ExtraProperties {
    fn as_ldap_attributes(&self) -> LDAPAttributes {
        let mut attributes = LDAPAttributes::default();
        if let Some(uuid) = self.uuid.as_ref() {
            attributes.add_value("entryUUID", uuid.as_hyphenated().to_string());
        }
        if ! self.extra_attributes.is_empty() {
            attributes.add_value(super::OBJECT_CLASS, "extensibleObject");
        }
        for (k, vs) in self.extra_attributes.iter() {
            for v in vs.iter() {
                attributes.add_value(k, v);
            }
        }
        for v in self.extra_object_classes.iter() {
            attributes.add_value(super::OBJECT_CLASS, v);
        }
        attributes
    }
}
impl Mergeable<Self> for ExtraProperties {
    fn merge(&mut self, other: Self) {
        self.extra_attributes.merge(other.extra_attributes);
        self.extra_object_classes.merge(other.extra_object_classes);
        self.uuid.merge(other.uuid);
    }
}