//! TLV8 framing used by HomeKit-style AirPlay pairing messages.
//!
//! This module only handles the wire format. Pair-Setup state transitions,
//! SRP, and cryptographic verification live in separate modules.

use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub kind: u8,
    pub value: Vec<u8>,
}

impl Drop for Tlv {
    fn drop(&mut self) {
        // Pairing TLVs can carry SRP proofs, encrypted key material, and
        // controller signatures. Wipe the owned payload before releasing it.
        self.value.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tlv8Error {
    TruncatedHeader {
        offset: usize,
    },
    TruncatedValue {
        offset: usize,
        expected: usize,
        remaining: usize,
    },
}

impl std::fmt::Display for Tlv8Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader { offset } => {
                write!(formatter, "truncated TLV8 header at byte {offset}")
            }
            Self::TruncatedValue {
                offset,
                expected,
                remaining,
            } => write!(
                formatter,
                "truncated TLV8 value at byte {offset}: expected {expected} bytes, found {remaining}"
            ),
        }
    }
}

impl std::error::Error for Tlv8Error {}

/// Decode TLV8 records, joining consecutive fragments of the same type when
/// the preceding fragment has the maximum 255-byte length.
pub fn decode(input: &[u8]) -> Result<Vec<Tlv>, Tlv8Error> {
    let mut items: Vec<Tlv> = Vec::new();
    let mut offset = 0;

    while offset < input.len() {
        if input.len() - offset < 2 {
            return Err(Tlv8Error::TruncatedHeader { offset });
        }

        let kind = input[offset];
        let length = usize::from(input[offset + 1]);
        let value_offset = offset + 2;
        let remaining = input.len() - value_offset;
        if remaining < length {
            return Err(Tlv8Error::TruncatedValue {
                offset: value_offset,
                expected: length,
                remaining,
            });
        }

        let value = &input[value_offset..value_offset + length];
        if let Some(previous) = items.last_mut() {
            if previous.kind == kind
                && previous.value.len() >= 255
                && previous.value.len() % 255 == 0
            {
                previous.value.extend_from_slice(value);
                offset = value_offset + length;
                continue;
            }
        }

        items.push(Tlv {
            kind,
            value: value.to_vec(),
        });
        offset = value_offset + length;
    }

    Ok(items)
}

/// Encode TLV8 records, splitting values into consecutive fragments of at
/// most 255 bytes as required by the wire format.
pub fn encode(items: &[Tlv]) -> Vec<u8> {
    let mut output = Vec::new();

    for item in items {
        if item.value.is_empty() {
            output.extend_from_slice(&[item.kind, 0]);
            continue;
        }

        for chunk in item.value.chunks(usize::from(u8::MAX)) {
            output.push(item.kind);
            output.push(chunk.len() as u8);
            output.extend_from_slice(chunk);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::{Tlv, Tlv8Error, decode, encode};

    #[test]
    fn encodes_and_decodes_multiple_values() {
        let items = vec![
            Tlv {
                kind: 6,
                value: vec![2],
            },
            Tlv {
                kind: 3,
                value: vec![1, 2, 3, 4],
            },
        ];
        assert_eq!(decode(&encode(&items)).expect("decode TLV8"), items);
    }

    #[test]
    fn joins_fragmented_value_over_255_bytes() {
        let item = Tlv {
            kind: 3,
            value: (0..=255).collect(),
        };
        let encoded = encode(std::slice::from_ref(&item));
        assert_eq!(encoded[1], 255);
        assert_eq!(encoded[257], 3);
        assert_eq!(
            decode(&encoded).expect("decode fragmented value"),
            vec![item]
        );
    }

    #[test]
    fn preserves_repeated_values_when_previous_fragment_is_short() {
        let encoded = [6, 1, 1, 6, 1, 2];
        assert_eq!(
            decode(&encoded).expect("decode repeated values"),
            vec![
                Tlv {
                    kind: 6,
                    value: vec![1],
                },
                Tlv {
                    kind: 6,
                    value: vec![2],
                },
            ]
        );
    }

    #[test]
    fn rejects_truncated_header_and_value() {
        assert!(matches!(
            decode(&[6]),
            Err(Tlv8Error::TruncatedHeader { offset: 0 })
        ));
        assert!(matches!(
            decode(&[3, 4, 1, 2]),
            Err(Tlv8Error::TruncatedValue {
                expected: 4,
                remaining: 2,
                ..
            })
        ));
    }

    #[test]
    fn encodes_empty_values() {
        let item = Tlv {
            kind: 255,
            value: Vec::new(),
        };
        assert_eq!(encode(std::slice::from_ref(&item)), [255, 0]);
        assert_eq!(decode(&[255, 0]).expect("decode empty TLV"), vec![item]);
    }
}
