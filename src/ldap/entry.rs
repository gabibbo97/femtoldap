use super::{acl::LDAPACL, attributes::LDAPAttributes, datatypes::CIString, dn::LDAPDN, traits::Mergeable};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LDAPEntry {
    pub dn: LDAPDN,
    pub attributes: LDAPAttributes,
    pub acls: LDAPACL,
}
impl LDAPEntry {

    pub fn new(dn: LDAPDN, attributes: LDAPAttributes) -> Self {
        Self {
            acls: Default::default(),
            dn,
            attributes,
        }
    }

    pub fn can_perform_bind(&self) -> bool {
        let acl_valid = self.acls.can_access_self || !self.acls.can_access_suffixes.is_empty();
        let has_credentials = self.attributes.has_attribute(&CIString::new("userPassword"));
        acl_valid && has_credentials
    }

    pub fn matches_filter(&self, filter: &ldap3_proto::LdapFilter) -> bool {
        match filter {
            ldap3_proto::LdapFilter::And(ldap_filters) => ldap_filters.iter()
                .all(|filter| self.matches_filter(filter)),
            ldap3_proto::LdapFilter::Or(ldap_filters) => ldap_filters.iter()
                .any(|filter| self.matches_filter(filter)),
            ldap3_proto::LdapFilter::Not(ldap_filter) => !self.matches_filter(&ldap_filter),
            ldap3_proto::LdapFilter::Equality(attribute_name, attribute_value) => if let Some(attribute) = self.attributes.get_attribute(&CIString::new(attribute_name)) {
                attribute.values.iter()
                    .any(|value| value == attribute_value.as_bytes())
            } else {
                false
            },
            ldap3_proto::LdapFilter::Present(attribute) => self.attributes.has_attribute(&CIString::new(attribute)),
            ldap3_proto::LdapFilter::Substring(attribute_name, substring_filter) => if let Some(attribute) = self.attributes.get_attribute(&CIString::new(attribute_name)) {
                // assemble a regex
                let mut re = vec![];
                if let Some(starts_with) = &substring_filter.initial {
                    re.push(format!("^{starts_with}"));
                }
                for intermediate in &substring_filter.any {
                    re.push(format!(".*{}.*", regex::escape(&intermediate)));
                }
                if let Some(ends_with) = &substring_filter.final_ {
                    re.push(format!("{ends_with}$"));
                }
                let re = re.join("");
                let re = regex::Regex::new(&re).unwrap();

                // if any matches the regex
                attribute.values.iter()
                    .any(|value| re.is_match(&String::from_utf8_lossy(&value)))
            } else {
                false
            },
            f => {
                tracing::warn!(filter = ?f, "Unsupported filter");
                false
            },
        }
    }

    pub fn tidy(&mut self) {
        self.acls.tidy();
        self.attributes.tidy();
        self.dn.tidy();
    }

}
impl std::hash::Hash for LDAPEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.dn.hash(state);
    }
}
impl Mergeable<Self> for LDAPEntry {
    fn merge(&mut self, other: Self) {
        assert_eq!(self.dn, other.dn);
        self.attributes.merge(other.attributes);
        self.acls.merge(other.acls);
    }
}
