#[derive(Clone)]
pub struct CIString { raw: String, lower: String }
impl CIString {

    pub fn new(s: impl AsRef<str>) -> Self {
        Self {
            raw: s.as_ref().to_string(),
            lower: s.as_ref().to_lowercase(),
        }
    }

}
impl std::hash::Hash for CIString {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.lower.hash(state);
    }
}
impl PartialEq for CIString {
    fn eq(&self, other: &Self) -> bool {
        self.lower == other.lower
    }
}
impl Eq for CIString {}
impl PartialOrd for CIString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.lower.partial_cmp(&other.lower)
    }
}
impl Ord for CIString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.lower.cmp(&other.lower)
    }
}
impl std::fmt::Debug for CIString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}
impl std::fmt::Display for CIString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}
