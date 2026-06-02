//! Shared fixtures for the Nitro adapter tests. The "Nitro" attestation
//! material here is deliberately fake: byte patterns that look like a
//! plausible Nitro NSM document but are not signed and are not parseable as
//! a real COSE_Sign1 payload. The adapter never inspects the document
//! bytes' contents - it forwards them as opaque attestation evidence - so
//! deterministic fixtures are sufficient to exercise its behavior.

// Each integration-test binary compiles `common` separately, so items only
// used by one binary look unused to the other. The shared fixtures are
// genuinely shared; suppress the false-positive dead-code warnings here.
#![allow(dead_code)]

use std::cell::RefCell;

use coprocessor_nitro_enclave::{
    AttestationDigest, NitroAdapterConfig, NitroAttestationDoc, NitroAttestationDocSource,
    NitroSourceError,
};

pub const TEST_APPROVED_MEASUREMENT: AttestationDigest = AttestationDigest([0x5E; 32]);

/// 48-byte BLS12-381 G1 compressed public key fixture, matching the size
/// the MPC public configuration's `bls12-381-g1` suite expects.
pub const TEST_PUBLIC_KEY_LEN: usize = 48;

pub fn fake_enclave_public_key() -> Vec<u8> {
    vec![0x44; TEST_PUBLIC_KEY_LEN]
}

/// Fake Nitro attestation-document bytes. Not a real COSE_Sign1 payload;
/// the adapter only forwards them.
pub fn fake_attestation_document_bytes() -> Vec<u8> {
    vec![0x55; 96]
}

pub fn approved_config() -> NitroAdapterConfig {
    NitroAdapterConfig {
        approved_enclave_measurement: TEST_APPROVED_MEASUREMENT,
        expected_public_key_len: TEST_PUBLIC_KEY_LEN,
    }
}

pub fn valid_attestation_doc() -> NitroAttestationDoc {
    NitroAttestationDoc {
        pcr0: TEST_APPROVED_MEASUREMENT,
        enclave_public_key: fake_enclave_public_key(),
        document_bytes: fake_attestation_document_bytes(),
    }
}

/// One outcome a [`FakeNsm`] can be programmed to return: either a parsed
/// document or a transport-level source error.
pub enum FakeNsmOutcome {
    Doc(NitroAttestationDoc),
    SourceError(NitroSourceError),
}

/// Fake Nitro Security Module transport. Programmed with one outcome at a
/// time; the adapter test calls the source exactly once per assertion so
/// each test seeds a fresh fake.
pub struct FakeNsm {
    outcome: RefCell<Option<FakeNsmOutcome>>,
}

impl FakeNsm {
    pub fn returning(outcome: FakeNsmOutcome) -> Self {
        Self {
            outcome: RefCell::new(Some(outcome)),
        }
    }

    pub fn returning_doc(doc: NitroAttestationDoc) -> Self {
        Self::returning(FakeNsmOutcome::Doc(doc))
    }

    pub fn returning_error(error: NitroSourceError) -> Self {
        Self::returning(FakeNsmOutcome::SourceError(error))
    }
}

impl NitroAttestationDocSource for FakeNsm {
    fn fetch_attestation_doc(&self) -> Result<NitroAttestationDoc, NitroSourceError> {
        match self
            .outcome
            .borrow_mut()
            .take()
            .expect("FakeNsm outcome already consumed")
        {
            FakeNsmOutcome::Doc(doc) => Ok(doc),
            FakeNsmOutcome::SourceError(error) => Err(error),
        }
    }
}
