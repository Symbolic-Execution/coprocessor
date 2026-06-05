//! Shared fixture helpers for MPC public configuration tests.

use std::cell::RefCell;

use coprocessor_mpc::{
    AttestationDigest, ChainId, DomainId, KeyId, MpcConfigExpectations, MpcConfigSource,
    MpcConfigSourceError, MpcSuite,
};

pub const TEST_CHAIN_ID: ChainId = ChainId(1);
pub const TEST_DOMAIN_ID: DomainId = DomainId([0x11; 32]);
pub const TEST_KEY_ID: KeyId = KeyId([0x22; 32]);
pub const TEST_ENCLAVE_MEASUREMENT: AttestationDigest = AttestationDigest([0x33; 32]);
pub const TEST_SUITE: MpcSuite = MpcSuite::Bls12_381G1;

pub fn matching_expectations() -> MpcConfigExpectations {
    MpcConfigExpectations {
        chain_id: TEST_CHAIN_ID,
        domain_id: TEST_DOMAIN_ID,
        suite: TEST_SUITE,
    }
}

/// Wire-shaped JSON payload that matches [`matching_expectations`]. The
/// public key is a 48-byte sequence so it satisfies BLS12-381 G1's shape.
pub fn valid_config_json() -> String {
    build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ])
}

pub enum JsonValue<'a> {
    Uint(u64),
    Str(&'a str),
}

pub fn build_json(fields: &[(&str, JsonValue<'_>)]) -> String {
    let mut out = String::from("{");
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(key);
        out.push_str("\":");
        match value {
            JsonValue::Uint(n) => out.push_str(&n.to_string()),
            JsonValue::Str(s) => {
                out.push('"');
                out.push_str(s);
                out.push('"');
            }
        }
    }
    out.push('}');
    out
}

pub fn hex32(byte: u8) -> String {
    hex_bytes(byte, 32)
}

pub fn hex_bytes(byte: u8, len: usize) -> String {
    let mut out = String::from("0x");
    for _ in 0..len {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Fake [`MpcConfigSource`] that returns whatever payload the test seeded it
/// with. Useful for exercising the parse + compatibility pipeline with
/// fixed wire input.
pub struct StubSource {
    body: String,
}

impl StubSource {
    pub fn new(body: impl Into<String>) -> Self {
        Self { body: body.into() }
    }
}

impl MpcConfigSource for StubSource {
    fn fetch(&self) -> Result<String, MpcConfigSourceError> {
        Ok(self.body.clone())
    }
}

/// Fake source that always fails with a transient availability error.
pub struct UnavailableSource {
    pub detail: &'static str,
}

impl MpcConfigSource for UnavailableSource {
    fn fetch(&self) -> Result<String, MpcConfigSourceError> {
        Err(MpcConfigSourceError::Unavailable {
            detail: self.detail.to_string(),
        })
    }
}

/// Fake source that returns `Unavailable` once then succeeds on subsequent
/// calls. Used to assert the load function treats the first error as
/// transient and lets a retry policy reach success.
pub struct FlakyOnceSource {
    body: String,
    failed: RefCell<bool>,
}

impl FlakyOnceSource {
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            failed: RefCell::new(false),
        }
    }
}

impl MpcConfigSource for FlakyOnceSource {
    fn fetch(&self) -> Result<String, MpcConfigSourceError> {
        let mut failed = self.failed.borrow_mut();
        if !*failed {
            *failed = true;
            Err(MpcConfigSourceError::Unavailable {
                detail: "transient: connection refused".to_string(),
            })
        } else {
            Ok(self.body.clone())
        }
    }
}
