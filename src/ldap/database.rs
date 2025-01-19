use std::{collections::{HashMap, HashSet}, sync::Arc};

use super::{datatypes::CIString, dn::LDAPDN, entry::LDAPEntry};

#[derive(Default)]
pub struct LDAPReadOnlyInMemoryDatabase {
    // all entities, by their DN
    entries: HashMap<LDAPDN, Arc<LDAPEntry>>,

    // login entities, i.e. entities for which login is possible
    login_entries: HashMap<LDAPDN, Arc<LDAPEntry>>,

    // indexes
    attr_index_names: HashSet<CIString>,
    attr_eq_index: HashMap<(CIString, Vec<u8>), HashSet<Arc<LDAPEntry>>>,
    attr_ex_index: HashMap<CIString, HashSet<Arc<LDAPEntry>>>,

    // dn suffixes
    dn_suffixes_indexes: HashMap<LDAPDN, HashSet<Arc<LDAPEntry>>>,
}
impl LDAPReadOnlyInMemoryDatabase {

    pub fn from_entries(entries: impl IntoIterator<Item = LDAPEntry>) -> Self {
        let mut instance = Self::default();
        for mut entry in entries {
            entry.tidy();
            instance.add_entry(Arc::new(entry));
        }
        instance.tidy();
        instance
    }

    pub fn add_entry(&mut self, entry: Arc<LDAPEntry>) {
        // assert entry does not exist
        assert!(!self.entries.contains_key(&entry.dn), "Entry already exists {entry:?}");

        // add to all entities
        self.entries.insert(entry.dn.clone(), entry.clone());

        // add to login entities
        if entry.can_perform_bind() {
            self.login_entries.insert(entry.dn.clone(), entry.clone());
        }

        // index attributes
        const INDEXED_ATTRIBUTES: &'static [&'static str] = &[
            "cn",
            "mail",
            "mailAlias",
            "memberOf",
            "objectClass",
            "uid",
            "uniqueMember",
        ];
        for indexed_attribute in INDEXED_ATTRIBUTES {
            // get attribute from entry
            if let Some(attribute) = entry.attributes.get_attribute(&CIString::new(indexed_attribute)) {
                // add to indexed attributes names
                self.attr_index_names.insert(CIString::new(indexed_attribute));

                // index attribute values
                for attribute_value in attribute.values.iter() {
                    // attribute equality index
                    self.attr_eq_index.entry((CIString::new(indexed_attribute), attribute_value.to_vec()))
                        .or_default()
                        .insert(entry.clone());

                    // attribute existence index
                    self.attr_ex_index.entry(CIString::new(indexed_attribute))
                        .or_default()
                        .insert(entry.clone());
                }
            }
        }

        // index suffixes
        for suffix_len in 0..entry.dn.len() {
            let suffix = LDAPDN::from_iter(entry.dn.iter().rev().take(suffix_len).map(|(k,v)| (k.to_string(), v.to_string())).rev());
            self.dn_suffixes_indexes.entry(suffix)
                .or_default()
                .insert(entry.clone());
        }
    }

    pub fn do_bind(&self, dn: &LDAPDN, password: impl AsRef<str>) ->  Option<Arc<LDAPEntry>> {
        if let Some(entry) = self.login_entries.get(dn) {
            if entry.attributes.check_password(password) {
                return Some(entry.clone());
            }
        }
        None
    }

    #[tracing::instrument(skip(self))]
    pub fn search(&self, base_dn: &LDAPDN, filter: &ldap3_proto::LdapFilter) -> HashSet<Arc<LDAPEntry>> {
        if let Some(entry) = self.entries.get(&base_dn) {
            // single entry lookup
            if entry.matches_filter(filter) {
                HashSet::from([ entry.clone() ])
            } else {
                HashSet::with_capacity(0)
            }
        } else if let Some(entries) = self.dn_suffixes_indexes.get(base_dn) {
            // suffix search
            match filter {
                // not
                ldap3_proto::LdapFilter::Not(ldap_filter) => {
                    let excluded_entries = self.search(base_dn, ldap_filter);
                    entries.difference(&excluded_entries).cloned().collect()
                },
                // and
                ldap3_proto::LdapFilter::And(ldap_filters) => if ldap_filters.is_empty() {
                    HashSet::with_capacity(0)
                } else {
                    let mut entries = entries.clone();
                    for sub_filter in ldap_filters {
                        let sub_entries = self.search(base_dn, sub_filter);
                        entries = entries.intersection(&sub_entries).cloned().collect();
                        if entries.is_empty() {
                            break
                        }
                    }
                    entries
                },
                // or
                ldap3_proto::LdapFilter::Or(ldap_filters) => if ldap_filters.is_empty() {
                    HashSet::with_capacity(0)
                } else {
                    ldap_filters.iter()
                        .map(|sub_filter| self.search(base_dn, sub_filter))
                        .reduce(|mut acc, mut elem| {
                            acc.extend(elem.drain());
                            acc
                        })
                        .unwrap()
                },
                // equality
                ldap3_proto::LdapFilter::Equality(attribute_name, attribute_value) => {
                    let attribute_name = CIString::new(attribute_name);
                    if self.attr_index_names.contains(&attribute_name) {
                        if let Some(filtered) = self.attr_eq_index.get(&(attribute_name, attribute_value.as_bytes().to_vec())) {
                            entries.intersection(filtered).cloned().collect()
                        } else {
                            HashSet::with_capacity(0)
                        }
                    } else {
                        entries.iter()
                            .filter(|entity| if let Some(attribute) = entity.attributes.get_attribute(&attribute_name) {
                                attribute.values.iter()
                                    .any(|value| attribute_value.as_bytes() == value)
                            } else {
                                false
                            })
                            .cloned()
                            .collect()
                    }
                },
                // present
                ldap3_proto::LdapFilter::Present(attribute) => {
                    let attribute_name = CIString::new(attribute);
                    if self.attr_index_names.contains(&attribute_name) {
                        if let Some(filtered) = self.attr_ex_index.get(&attribute_name) {
                            entries.intersection(filtered).cloned().collect()
                        } else {
                            HashSet::with_capacity(0)
                        }
                    } else {
                        entries.iter()
                            .filter(|entity| if let Some(..) = entity.attributes.get_attribute(&attribute_name) {
                                true
                            } else {
                                false
                            })
                            .cloned()
                            .collect()
                    }
                },
                // substring
                ldap3_proto::LdapFilter::Substring(..) => {
                    entries.iter()
                        .filter(|entry| entry.matches_filter(filter))
                        .cloned()
                        .collect()
                },
                f => {
                    tracing::warn!(filter = ?f, "Unsupported filter");
                    HashSet::with_capacity(0)
                },
            }
        } else {
            HashSet::with_capacity(0)
        }
    }

    pub fn tidy(&mut self) {
        // shrink arrays
        self.entries.shrink_to_fit();
        self.login_entries.shrink_to_fit();
        self.attr_index_names.shrink_to_fit();
        self.attr_eq_index.shrink_to_fit();
        self.attr_ex_index.shrink_to_fit();
        self.dn_suffixes_indexes.shrink_to_fit();
    }

}
impl std::fmt::Debug for LDAPReadOnlyInMemoryDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LDAPReadOnlyInMemoryDatabase\n")?;
        // entries
        writeln!(f, "  entries DNs ({} entries)", self.entries.len())?;
        for dn in self.entries.keys() {
            writeln!(f, "    {dn}")?;
        }
        // login entries
        writeln!(f, "  entries DNs with bind capability ({} entries)", self.login_entries.len())?;
        for dn in self.login_entries.keys() {
            writeln!(f, "    {dn}")?;
        }
        // attribute value indexes
        writeln!(f, "  Attribute value index ({} entries)", self.attr_eq_index.len())?;
        for ((attr_name, attr_value), entries) in self.attr_eq_index.iter() {
            let attr_value = String::from_utf8_lossy(&attr_value);
            writeln!(f, "    {attr_name}={attr_value} ({} entries)", entries.len())?;
            for (i, entry) in entries.iter().enumerate() {
                writeln!(f, "      [{}] => {}", i + 1, entry.dn)?;
            }
        }
        // attribute presence indexes
        writeln!(f, "  Attribute presence index ({} entries)", self.attr_ex_index.len())?;
        let mut attr_names = self.attr_ex_index.keys().collect::<Vec<_>>();
        attr_names.sort_unstable();
        for attr_name in attr_names {
            let entries = self.attr_ex_index.get(attr_name).unwrap();
            writeln!(f, "    {attr_name} ({} entries)", entries.len())?;
            for (i, entry) in entries.iter().enumerate() {
                writeln!(f, "      [{}] => {}", i + 1, entry.dn)?;
            }
        }
        // dn suffixes
        writeln!(f, "  DN suffix index ({} entries)", self.dn_suffixes_indexes.len())?;
        let mut suffixes = self.dn_suffixes_indexes.keys().collect::<Vec<_>>();
        suffixes.sort_unstable();
        for dn in suffixes {
            writeln!(f, "    {dn}")?;
            for (i, entry) in self.dn_suffixes_indexes.get(dn).unwrap().iter().enumerate() {
                writeln!(f, "      [{}] => {}", i + 1, entry.dn)?;
            }
        }
        Ok(())
    }
}
