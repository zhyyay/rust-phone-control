//! Binary and XML property-list codec used by AirPlay control messages.
//!
//! Request and response sizes are bounded by the RTSP layer before these
//! helpers are called. This module intentionally contains no protocol policy.

use std::io::Cursor;

use ::plist::{Error, Value};

/// Decode a property-list payload. The plist crate accepts both XML and binary
/// encodings; AirPlay binary payloads are identified by the bplist00 header.
pub(super) fn decode(bytes: &[u8]) -> Result<Value, Error> {
    Value::from_reader(Cursor::new(bytes))
}

/// Encode a value using Apple's binary property-list representation.
pub(super) fn encode_binary(value: &Value) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    value.to_writer_binary(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode_binary};
    use ::plist::{Dictionary, Value};

    fn sample_value() -> Value {
        let mut nested = Dictionary::new();
        nested.insert("enabled".into(), Value::Boolean(true));
        nested.insert("count".into(), Value::Integer(7.into()));

        let mut root = Dictionary::new();
        root.insert("name".into(), Value::String("Rust Phone Control".into()));
        root.insert("nested".into(), Value::Dictionary(nested));
        root.insert(
            "items".into(),
            Value::Array(vec![
                Value::String("first".into()),
                Value::Boolean(false),
            ]),
        );
        Value::Dictionary(root)
    }

    #[test]
    fn binary_encoding_has_apple_header() {
        let bytes = encode_binary(&sample_value()).expect("encode binary plist");
        assert!(bytes.starts_with(b"bplist00"));
    }

    #[test]
    fn binary_dictionary_array_and_scalar_values_round_trip() {
        let expected = sample_value();
        let bytes = encode_binary(&expected).expect("encode binary plist");
        let actual = decode(&bytes).expect("decode binary plist");
        assert_eq!(actual, expected);
    }

    #[test]
    fn xml_property_list_can_also_be_decoded() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict><key>qualifier</key><array><string>deviceID</string></array></dict></plist>"#;
        let value = decode(xml).expect("decode XML plist");
        let dict = value.as_dictionary().expect("dictionary root");
        assert!(dict.contains_key("qualifier"));
    }

    #[test]
    fn invalid_property_list_is_rejected() {
        assert!(decode(b"not a plist").is_err());
    }
}
