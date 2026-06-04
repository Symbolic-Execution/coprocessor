//! Minimal hand-rolled JSON codec for the Coprocessor API surface.
//!
//! The decoder targets the small subset of JSON the transport actually emits:
//! one top-level value, which is either a quoted string (used for envelope
//! base64 payloads) or a flat object whose values are JSON strings or
//! unsigned-integer numbers (used for ChainEventRef). Nested objects, arrays,
//! floats, escape sequences inside strings, signed numbers, booleans, and
//! `null` are all rejected with stable [`JsonParseError`] variants.
//!
//! Errors name the parsing step that failed and the field where the failure
//! was observed when one is known. They never include payload bytes.

use crate::HexDecodeError;
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum JsonParseError {
    /// The input was not the expected top-level shape (object or string).
    #[error("unexpected token: expected {expected}")]
    UnexpectedToken { expected: &'static str },
    /// The input ended before the document was complete.
    #[error("unexpected end of input: expected {expected}")]
    UnexpectedEndOfInput { expected: &'static str },
    /// The input contained extra non-whitespace characters after the document.
    #[error("trailing content after JSON document")]
    TrailingContent,
    /// A string used an unsupported feature (escape sequences are not allowed
    /// in transport strings, since payloads are hex or base64).
    #[error("unsupported string escape in JSON")]
    UnsupportedStringEscape,
    /// A digit-starting number could not be parsed as a canonical unsigned
    /// integer (for example, leading zeros or out of `u64` range).
    #[error("invalid unsigned number in field {field}")]
    InvalidUnsignedNumber { field: &'static str },
    /// Object had a duplicate key.
    #[error("duplicate field {field}")]
    DuplicateField { field: &'static str },
    /// Object was missing an expected key.
    #[error("missing field {field}")]
    MissingField { field: &'static str },
    /// Object had an unexpected key.
    #[error("unexpected field in JSON object")]
    UnexpectedField,
    /// A field value did not have the expected JSON shape.
    #[error("wrong shape for field {field}: expected {expected}")]
    FieldShape {
        field: &'static str,
        expected: &'static str,
    },
    /// A field hex string failed to decode.
    #[error("invalid hex in field {field}")]
    InvalidHex {
        field: &'static str,
        #[source]
        error: HexDecodeError,
    },
    /// A parsed integer did not fit the field's narrower numeric type.
    #[error("integer overflow in field {field}: expected {expected}")]
    IntegerOverflow {
        field: &'static str,
        expected: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Object writer helpers (used by lib.rs)
// ---------------------------------------------------------------------------

pub fn write_object_open(out: &mut String) {
    out.push('{');
}

pub fn write_object_close(out: &mut String) {
    out.push('}');
}

pub fn write_string_field(out: &mut String, key: &str, value: &str, leading_comma: bool) {
    if leading_comma {
        out.push(',');
    }
    write_key(out, key);
    write_string_literal(out, value);
}

pub fn write_uint_field(out: &mut String, key: &str, value: u64, leading_comma: bool) {
    if leading_comma {
        out.push(',');
    }
    write_key(out, key);
    out.push_str(&value.to_string());
}

fn write_key(out: &mut String, key: &str) {
    write_string_literal(out, key);
    out.push(':');
}

fn write_string_literal(out: &mut String, value: &str) {
    // Strings on this transport are hex or base64 — both restricted alphabets
    // with no characters that need JSON escaping. The writer asserts that
    // invariant rather than emitting escapes that the reader would reject.
    debug_assert!(
        value
            .bytes()
            .all(|b| matches!(b, b' '..=b'~') && b != b'"' && b != b'\\'),
        "JSON transport writer received a string that would require escaping",
    );
    out.push('"');
    out.push_str(value);
    out.push('"');
}

// ---------------------------------------------------------------------------
// Top-level parsers
// ---------------------------------------------------------------------------

pub fn parse_string(text: &str) -> Result<String, JsonParseError> {
    let mut reader = Reader::new(text);
    reader.skip_whitespace();
    let value = reader.read_string_value()?;
    reader.skip_whitespace();
    reader.require_end()?;
    Ok(value)
}

pub fn parse_object(text: &str) -> Result<JsonObject, JsonParseError> {
    let mut reader = Reader::new(text);
    reader.skip_whitespace();
    let fields = reader.read_object()?;
    reader.skip_whitespace();
    reader.require_end()?;
    Ok(JsonObject { fields })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FieldValue {
    String(String),
    Uint(u64),
}

/// Parsed flat JSON object with string and unsigned-integer fields. Callers
/// consume fields with [`JsonObject::take_string`] or
/// [`JsonObject::take_uint`], then call [`JsonObject::finish`] to reject any
/// keys the consumer did not claim.
pub struct JsonObject {
    fields: Vec<(String, FieldValue)>,
}

impl JsonObject {
    pub fn take_uint(&mut self, key: &'static str) -> Result<u64, JsonParseError> {
        match self.take(key)? {
            FieldValue::Uint(value) => Ok(value),
            FieldValue::String(_) => Err(JsonParseError::FieldShape {
                field: key,
                expected: "unsigned integer",
            }),
        }
    }

    pub fn take_string(&mut self, key: &'static str) -> Result<String, JsonParseError> {
        match self.take(key)? {
            FieldValue::String(value) => Ok(value),
            FieldValue::Uint(_) => Err(JsonParseError::FieldShape {
                field: key,
                expected: "string",
            }),
        }
    }

    pub fn finish(self) -> Result<(), JsonParseError> {
        if self.fields.is_empty() {
            Ok(())
        } else {
            Err(JsonParseError::UnexpectedField)
        }
    }

    fn take(&mut self, key: &'static str) -> Result<FieldValue, JsonParseError> {
        let position = self
            .fields
            .iter()
            .position(|(name, _)| name == key)
            .ok_or(JsonParseError::MissingField { field: key })?;
        Ok(self.fields.remove(position).1)
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn expect(&mut self, byte: u8, expected: &'static str) -> Result<(), JsonParseError> {
        match self.bump() {
            Some(b) if b == byte => Ok(()),
            Some(_) => Err(JsonParseError::UnexpectedToken { expected }),
            None => Err(JsonParseError::UnexpectedEndOfInput { expected }),
        }
    }

    fn require_end(&self) -> Result<(), JsonParseError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(JsonParseError::TrailingContent)
        }
    }

    fn read_string_value(&mut self) -> Result<String, JsonParseError> {
        self.expect(b'"', "string")?;
        let start = self.pos;
        while let Some(byte) = self.bump() {
            match byte {
                b'"' => {
                    let raw = &self.bytes[start..self.pos - 1];
                    return Ok(String::from_utf8_lossy(raw).into_owned());
                }
                b'\\' => return Err(JsonParseError::UnsupportedStringEscape),
                b if b < 0x20 => {
                    return Err(JsonParseError::UnexpectedToken {
                        expected: "printable string character",
                    });
                }
                _ => {}
            }
        }
        Err(JsonParseError::UnexpectedEndOfInput {
            expected: "closing quote",
        })
    }

    fn read_object(&mut self) -> Result<Vec<(String, FieldValue)>, JsonParseError> {
        self.expect(b'{', "object")?;
        self.skip_whitespace();
        let mut fields: Vec<(String, FieldValue)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(fields);
        }
        loop {
            self.skip_whitespace();
            let key = self.read_string_value()?;
            self.skip_whitespace();
            self.expect(b':', "':'")?;
            self.skip_whitespace();
            let value = self.read_field_value(&key)?;
            if fields.iter().any(|(existing, _)| existing == &key) {
                // The field name is user-controlled, but every key the writer
                // emits is a static identifier; we surface duplicates as
                // generic to avoid threading a `&'static str` through the
                // parser.
                return Err(JsonParseError::DuplicateField {
                    field: "<duplicate>",
                });
            }
            fields.push((key, value));
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(fields),
                Some(_) => {
                    return Err(JsonParseError::UnexpectedToken {
                        expected: "',' or '}'",
                    });
                }
                None => {
                    return Err(JsonParseError::UnexpectedEndOfInput {
                        expected: "',' or '}'",
                    });
                }
            }
        }
    }

    fn read_field_value(&mut self, key: &str) -> Result<FieldValue, JsonParseError> {
        match self.peek() {
            Some(b'"') => Ok(FieldValue::String(self.read_string_value()?)),
            Some(b'0'..=b'9') => Ok(FieldValue::Uint(self.read_uint(key)?)),
            Some(_) => Err(JsonParseError::FieldShape {
                field: stable_field_name(key),
                expected: "string or unsigned integer",
            }),
            None => Err(JsonParseError::UnexpectedEndOfInput {
                expected: "field value",
            }),
        }
    }

    fn read_uint(&mut self, key: &str) -> Result<u64, JsonParseError> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let raw = &self.bytes[start..self.pos];
        let text = std::str::from_utf8(raw).expect("ascii digits");
        // Reject leading zeros (canonical JSON has no `01`) but keep `0`.
        if text.len() > 1 && text.starts_with('0') {
            return Err(JsonParseError::InvalidUnsignedNumber {
                field: stable_field_name(key),
            });
        }
        text.parse::<u64>()
            .map_err(|_| JsonParseError::InvalidUnsignedNumber {
                field: stable_field_name(key),
            })
    }
}

/// Borrow a stable field name back from known parsed keys. Unknown keys can
/// still fail while their value is being parsed, before [`JsonObject::finish`]
/// rejects them as unexpected, so they use a generic non-payload field name.
fn stable_field_name(key: &str) -> &'static str {
    match key {
        "chain_id" => "chain_id",
        "block_number" => "block_number",
        "block_hash" => "block_hash",
        "tx_hash" => "tx_hash",
        "log_index" => "log_index",
        _ => "<unknown>",
    }
}
