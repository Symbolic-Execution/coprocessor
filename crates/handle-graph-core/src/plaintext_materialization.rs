//! Materialize a Plaintext Handle into a real `SystemCiphertextV1` envelope
//! bound to a `SystemHandleAadV1`.
//!
//! [`HandleFromPlaintextV1`] events carry a Public Plaintext Value. The
//! Coprocessor Host turns each one into a Ready Handle whose payload is a
//! canonical CBOR `SystemCiphertextV1` envelope with its embedded AAD bound
//! to the spec-shaped tuple `(chain_id, domain_id, handle_id, type_tag,
//! key_id)`. After materialization the Public Plaintext Value itself is
//! discarded: the persisted handle payload is the envelope and a
//! materialization receipt, not the raw bytes that arrived on chain.
//!
//! This module owns the AAD assembly, type-tag selection, envelope encoding,
//! and the small receipt format. It is the only place in the host that
//! constructs a Plaintext Handle's `SystemCiphertextV1` payload.

use coprocessor_ciphertext_binding::{
    self as cbinding, SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};

use crate::{HandleType, MaterializationReceipt, PlaintextHandle, SystemCiphertextV1};

/// Type tag the Coordinator and MPC use for the initial `suint256` Handle
/// type. Matches the spec wire form.
pub const SUINT256_TYPE_TAG: &str = "suint256";

/// Type tag the Coordinator and MPC use for the initial `sbool` Handle type.
/// Matches the spec wire form.
pub const SBOOL_TYPE_TAG: &str = "sbool";

const AAD_VERSION: u8 = 1;
const ENVELOPE_VERSION: u8 = 1;
const RECEIPT_VERSION: u8 = 1;
const RECEIPT_MARKER: &str = "plaintext-materialization-v1";

/// Builds Plaintext Handle `SystemCiphertextV1` envelopes whose embedded
/// `SystemHandleAadV1` binds the host-configured active MPC `key_id`.
///
/// Chain id, domain id, handle id, and type tag come from the Plaintext
/// Handle event itself; the active key id is the only piece of MPC public
/// configuration the materializer carries.
///
/// The materializer is a value, not a trait: every host runs the same AAD
/// assembly and envelope shape. Configuration that varies (the active key
/// id) is a field, not a seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaintextMaterializer {
    active_key_id: cbinding::KeyId,
}

impl PlaintextMaterializer {
    /// Construct a materializer that binds every produced envelope to
    /// `active_key_id`. The host populates this from the MPC public
    /// configuration's active key id.
    pub fn new(active_key_id: cbinding::KeyId) -> Self {
        Self { active_key_id }
    }

    /// The active key id this materializer binds into every produced AAD.
    pub fn active_key_id(&self) -> cbinding::KeyId {
        self.active_key_id
    }

    /// Materialize one [`PlaintextHandle`] into the payload values the host
    /// stores in [`crate::HandleState::Ready`]. The Public Plaintext Value
    /// is read for type-tag selection and AAD assembly only; its raw bytes
    /// do not appear in either output.
    pub fn materialize(&self, plaintext: &PlaintextHandle) -> MaterializedPlaintextHandle {
        let aad = self.build_aad(plaintext);
        let aad_bytes = aad.encode();
        let envelope = EnvelopeSystemCiphertextV1 {
            version: ENVELOPE_VERSION,
            aad: aad_bytes.clone(),
            wrapped_key: Vec::new(),
            ciphertext: Vec::new(),
        };
        let system_ciphertext = SystemCiphertextV1(envelope.encode());
        let materialization_receipt = MaterializationReceipt(encode_receipt(&aad_bytes));
        MaterializedPlaintextHandle {
            system_ciphertext,
            materialization_receipt,
        }
    }

    fn build_aad(&self, plaintext: &PlaintextHandle) -> SystemHandleAadV1 {
        SystemHandleAadV1 {
            version: AAD_VERSION,
            chain_id: plaintext.handle_key.chain_id.0,
            domain_id: cbinding::DomainId(plaintext.domain_id.0),
            handle_id: cbinding::HandleId(plaintext.handle_key.handle_id.0),
            type_tag: type_tag_for_handle_type(plaintext.handle_type).to_string(),
            key_id: self.active_key_id,
        }
    }
}

impl Default for PlaintextMaterializer {
    /// A materializer with an unset active key id. Suitable for tests that
    /// exercise other parts of the Handle Graph without configuring MPC.
    /// Production code should always construct an explicit materializer via
    /// [`PlaintextMaterializer::new`].
    fn default() -> Self {
        Self::new(cbinding::KeyId([0u8; 32]))
    }
}

/// Outputs of [`PlaintextMaterializer::materialize`]: the bytes the host
/// stores under the Ready Handle's `system_ciphertext` and
/// `materialization_receipt` slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedPlaintextHandle {
    pub system_ciphertext: SystemCiphertextV1,
    pub materialization_receipt: MaterializationReceipt,
}

/// Returns the spec-defined type tag for `handle_type`.
pub const fn type_tag_for_handle_type(handle_type: HandleType) -> &'static str {
    match handle_type {
        HandleType::Suint256 => SUINT256_TYPE_TAG,
        HandleType::Sbool => SBOOL_TYPE_TAG,
    }
}

/// Encode the Plaintext Materialization Receipt as canonical CBOR:
///
/// `[receipt_version: uint, marker: text, aad_bytes: bstr]`.
///
/// The marker distinguishes the receipt from the AAD bytes it contains, so
/// audit code reading the byte blob can tell which side of the materialization
/// it is looking at. The AAD bytes are the canonical encoding of the same
/// [`SystemHandleAadV1`] embedded in the envelope; replaying the receipt
/// reproduces the binding tuple without ever touching the Public Plaintext
/// Value.
fn encode_receipt(aad_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_array_header(&mut out, 3);
    write_unsigned_integer(&mut out, RECEIPT_VERSION as u64);
    write_text_string(&mut out, RECEIPT_MARKER);
    write_byte_string(&mut out, aad_bytes);
    out
}

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTE_STRING: u8 = 2;
const MAJOR_TEXT_STRING: u8 = 3;
const MAJOR_ARRAY: u8 = 4;

fn write_array_header(out: &mut Vec<u8>, len: usize) {
    write_cbor_header(out, MAJOR_ARRAY, len as u64);
}

fn write_unsigned_integer(out: &mut Vec<u8>, value: u64) {
    write_cbor_header(out, MAJOR_UINT, value);
}

fn write_byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_cbor_header(out, MAJOR_BYTE_STRING, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_text_string(out: &mut Vec<u8>, text: &str) {
    write_cbor_header(out, MAJOR_TEXT_STRING, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

fn write_cbor_header(out: &mut Vec<u8>, major: u8, value: u64) {
    let head = major << 5;
    if value <= 23 {
        out.push(head | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(head | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(head | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(head | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}
