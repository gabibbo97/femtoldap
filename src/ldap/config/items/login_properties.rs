use crate::ldap::{attributes::LDAPAttributes, config::traits::AsLDAPAttributes, traits::Mergeable};

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct LoginProperties {
    /// Credentials used to authenticate
    #[serde(alias = "userPassword")] pub password: Option<String>,
}
impl AsLDAPAttributes for LoginProperties {
    fn as_ldap_attributes(&self) -> LDAPAttributes {
        let mut attributes = LDAPAttributes::default();
        attributes.add_value(super::OBJECT_CLASS, "simpleSecurityObject");
        if let Some(password) = self.password.as_ref() {
            attributes.add_value("userPassword", password);
        }
        attributes
    }
}
impl Mergeable<Self> for LoginProperties {
    fn merge(&mut self, other: Self) {
        self.password.merge(other.password);
    }
}