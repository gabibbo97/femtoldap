use std::{collections::VecDeque, fmt::Write};

use super::traits::Mergeable;

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LDAPDN(VecDeque<(String, String)>);
impl LDAPDN {
    //
    // Constructor
    //
    pub fn empty() -> Self {
        Self(VecDeque::with_capacity(0))
    }

    //
    // Modifiers
    //
    pub fn add_prefix(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.push_front((k.into(), v.into()));
    }
    pub fn add_suffix(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.push_back((k.into(), v.into()));
    }
    pub fn with_prefix(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.add_prefix(k, v);
        self
    }

    //
    // Matchers
    //
    pub fn matches_suffix(&self, suffix: &LDAPDN) -> bool
    {
        self.len() >= suffix.len()
            && 
        self.iter().rev()
            .zip(suffix.iter().rev())
            .all(|(a, b)| a == b)

    }

    pub fn uuid(&self) -> uuid::Uuid {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_X500, self.to_string().as_bytes())
    }

    pub fn tidy(&mut self) {
        self.0.shrink_to_fit();
    }

}
impl std::fmt::Debug for LDAPDN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_char('"')?;
        if ! self.is_empty() {
            <Self as std::fmt::Display>::fmt(self, f)?;
        }
        f.write_char('"')?;
        Ok(())
    }
}
impl std::fmt::Display for LDAPDN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            f.write_str("<root DSE>")
        } else {
            for (i, (k, v)) in self.iter().enumerate() {
                if i != 0 {
                    f.write_str(",")?;
                }
                f.write_str(&k)?;
                f.write_str("=")?;
                f.write_str(&v)?;
            }
            Ok(())
        }
    }
}
impl std::ops::Deref for LDAPDN {
    type Target = VecDeque<(String, String)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for LDAPDN {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl std::str::FromStr for LDAPDN {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut dn = LDAPDN::empty();
        for component in s.split(',') {
            if component.is_empty() {
                continue;
            }
            if let Some((k, v)) = component.split_once('=') {
                if k.is_empty() {
                    return Err(anyhow::anyhow!("DN Component {component} is malformed (key is empty)"));
                }
                if v.is_empty() {
                    return Err(anyhow::anyhow!("DN Component {component} is malformed (value is empty)"));
                }
                dn.add_suffix(k, v);
            } else {
                return Err(anyhow::anyhow!("DN Component {component} is malformed"));
            }
        }
        Ok(dn)
    }
}
impl<'de> serde::Deserialize<'de> for LDAPDN {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}
impl serde::Serialize for LDAPDN {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let s = self.to_string();
        serializer.serialize_str(&s)
    }
}
impl Mergeable<Self> for LDAPDN {
    fn merge(&mut self, mut other: Self) {
        if self.is_empty() && !other.is_empty() {
            let _ = std::mem::swap(self, &mut other);
        }
    }
}
impl FromIterator<(String, String)> for LDAPDN {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self(VecDeque::from_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::ldap::dn::LDAPDN;

    #[test]
    fn test_ldap_dn_parsing() {
        // empty
        assert_eq!(LDAPDN::from_str("").unwrap(), LDAPDN::empty());

        // single element
        let dn = LDAPDN::from_str("dc=com").unwrap();
        assert_eq!(dn[0], ("dc".to_string(), "com".to_string()));

        // double element
        let dn = LDAPDN::from_str("dc=example,dc=com").unwrap();
        assert_eq!(dn[0], ("dc".to_string(), "example".to_string()));
        assert_eq!(dn[1], ("dc".to_string(), "com".to_string()));

        // triple element
        let dn = LDAPDN::from_str("dc=test,dc=example,dc=com").unwrap();
        assert_eq!(dn[0], ("dc".to_string(), "test".to_string()));
        assert_eq!(dn[1], ("dc".to_string(), "example".to_string()));
        assert_eq!(dn[2], ("dc".to_string(), "com".to_string()));
    }

    #[test]
    fn test_ldap_dn_suffix() {
        assert!(LDAPDN::from_str("").unwrap().matches_suffix(&LDAPDN::from_str("").unwrap()));
        assert!(LDAPDN::from_str("dc=com").unwrap().matches_suffix(&LDAPDN::from_str("").unwrap()));
        assert!(LDAPDN::from_str("dc=example,dc=com").unwrap().matches_suffix(&LDAPDN::from_str("dc=com").unwrap()));
        assert!(!LDAPDN::from_str("dc=example,dc=com").unwrap().matches_suffix(&LDAPDN::from_str("dc=org").unwrap()));
        assert!(LDAPDN::from_str("cn=test,ou=test,dc=example,dc=com").unwrap().matches_suffix(&LDAPDN::from_str("dc=example,dc=com").unwrap()));
        assert!(LDAPDN::from_str("cn=test,ou=test,dc=example,dc=com").unwrap().matches_suffix(&LDAPDN::from_str("ou=test,dc=example,dc=com").unwrap()));
        assert!(!LDAPDN::from_str("cn=test,ou=test,dc=example,dc=com").unwrap().matches_suffix(&LDAPDN::from_str("ou=test,dc=else,dc=com").unwrap()));
        assert!(!LDAPDN::from_str("dc=example,dc=com").unwrap().matches_suffix(&LDAPDN::from_str("cn=test,ou=test,dc=example,dc=com").unwrap()));
    }

}
