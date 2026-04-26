//! XML serialization helpers.
//!
//! CloudFront's wire format is REST-XML with `xmlns` carried on every
//! top-level response element. `quick-xml` doesn't emit a namespace from
//! a serde derive, so we wrap the serialized body to inject it.

use quick_xml::de::from_str;
use quick_xml::se::to_string_with_root;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::NAMESPACE;

const XML_DECL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

/// Serialize a serde value as `<Root xmlns="...">...</Root>` with a
/// leading XML declaration.
pub fn to_xml_root<T: Serialize>(root: &str, value: &T) -> Result<String, quick_xml::DeError> {
    let inner =
        to_string_with_root(root, value).map_err(|e| quick_xml::DeError::Custom(e.to_string()))?;
    Ok(inject_namespace(&inner, root))
}

fn inject_namespace(inner: &str, root: &str) -> String {
    let open_tag = format!("<{root}>");
    let open_with_ns = format!("<{root} xmlns=\"{NAMESPACE}\">");
    let stamped = if let Some(rest) = inner.strip_prefix(&open_tag) {
        format!("{open_with_ns}{rest}")
    } else {
        let self_close = format!("<{root}/>");
        if let Some(rest) = inner.strip_prefix(&self_close) {
            format!("<{root} xmlns=\"{NAMESPACE}\"/>{rest}")
        } else {
            inner.to_string()
        }
    };
    format!("{XML_DECL}{stamped}")
}

/// Parse an XML body into a serde-deserializable type.
pub fn from_xml_root<T: DeserializeOwned>(body: &[u8]) -> Result<T, quick_xml::DeError> {
    let s = std::str::from_utf8(body)
        .map_err(|e| quick_xml::DeError::Custom(format!("invalid utf-8 in body: {e}")))?;
    from_str(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Wrap {
        inner: String,
    }

    #[test]
    fn roundtrip_root_with_namespace() {
        let value = Wrap {
            inner: "hello".into(),
        };
        let xml = to_xml_root("Wrap", &value).unwrap();
        assert!(xml.contains("xmlns=\"http://cloudfront.amazonaws.com/doc/2020-05-31/\""));
        assert!(xml.contains("<Inner>hello</Inner>"));
        let parsed: Wrap = from_xml_root(xml.as_bytes()).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn empty_struct_renders_self_closing() {
        #[derive(Serialize, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Empty {}
        let xml = to_xml_root("Empty", &Empty {}).unwrap();
        assert!(xml.contains("<Empty xmlns=\"http://cloudfront.amazonaws.com/doc/2020-05-31/\"/>"));
    }
}
