//! XML serialization helpers for Route 53.

use quick_xml::de::from_str;
use serde::de::DeserializeOwned;

/// Parse an XML body into a serde-deserializable type.
pub fn from_xml_root<T: DeserializeOwned>(body: &[u8]) -> Result<T, quick_xml::DeError> {
    let s = std::str::from_utf8(body)
        .map_err(|e| quick_xml::DeError::Custom(format!("invalid utf-8 in body: {e}")))?;
    from_str(s)
}
