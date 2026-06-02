//! Shared fixtures and fake MPC source for To-Enclave Transformation tests.

use std::cell::RefCell;

use coprocessor_ciphertext_binding::{
    AttestationDigest, DomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId, KeyId, RequestId,
    SystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_handle_graph_core::ChainId;
use coprocessor_mpc_client::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};

pub const TEST_CHAIN_ID: ChainId = ChainId(1);
pub const TEST_REQUEST_ID: RequestId = RequestId([0x77; 32]);
pub const TEST_HANDLE_ID: HandleId = HandleId([0x88; 32]);
pub const TEST_DOMAIN_ID: DomainId = DomainId([0x11; 32]);
pub const TEST_KEY_ID: KeyId = KeyId([0x22; 32]);
pub const TEST_ATTESTATION_DIGEST: AttestationDigest = AttestationDigest([0x33; 32]);

/// 48-byte BLS12-381 G1 compressed public key placeholder for tests.
pub fn enclave_public_key() -> Vec<u8> {
    vec![0x44; 48]
}

/// Opaque attestation evidence bytes. Tests treat this as a sealed payload —
/// the client is expected to forward but never inspect.
pub fn attestation_bytes() -> Vec<u8> {
    vec![0x55; 96]
}

/// Build a [`SystemCiphertextV1`] whose AAD binds to the test request facts.
pub fn system_ciphertext_for_test_request() -> SystemCiphertextV1 {
    let aad = SystemHandleAadV1 {
        version: 1,
        chain_id: TEST_CHAIN_ID.0,
        domain_id: TEST_DOMAIN_ID,
        handle_id: TEST_HANDLE_ID,
        type_tag: "suint256".to_string(),
        key_id: TEST_KEY_ID,
    }
    .encode();
    SystemCiphertextV1 {
        version: 1,
        aad,
        wrapped_key: vec![0xAA; 32],
        ciphertext: vec![0xBB; 64],
    }
}

/// Build an [`EnclaveCiphertextV1`] whose AAD binds to the test request facts.
/// Production MPC returns this kind of envelope after the To-Enclave
/// Transformation succeeds.
pub fn enclave_ciphertext_for_test_request() -> EnclaveCiphertextV1 {
    let aad = EnclaveAadV1 {
        version: 1,
        chain_id: TEST_CHAIN_ID.0,
        domain_id: TEST_DOMAIN_ID,
        request_id: TEST_REQUEST_ID,
        handle_id: TEST_HANDLE_ID,
        type_tag: "suint256".to_string(),
        attestation_digest: TEST_ATTESTATION_DIGEST,
        key_id: TEST_KEY_ID,
    }
    .encode();
    EnclaveCiphertextV1 {
        version: 1,
        aad,
        wrapped_key: vec![0xCC; 32],
        ciphertext: vec![0xDD; 64],
    }
}

pub fn valid_request() -> ToEnclaveTransformationRequest {
    ToEnclaveTransformationRequest {
        request_id: TEST_REQUEST_ID,
        chain_id: TEST_CHAIN_ID,
        handle_id: TEST_HANDLE_ID,
        enclave_public_key: enclave_public_key(),
        enclave_measurement: TEST_ATTESTATION_DIGEST,
        attestation: attestation_bytes(),
        system_ciphertext: system_ciphertext_for_test_request(),
    }
}

/// One outcome the fake MPC server can be programmed to return: either a
/// typed protocol response or a transport-level source error.
pub enum FakeMpcOutcome {
    Response(MpcToEnclaveResponse),
    Source(MpcSourceError),
}

/// Fake MPC server. Tests seed it with one programmed outcome and assert
/// behavior of the client wrapped around it. The fake also records the
/// request it observed so tests can confirm the client forwarded the correct
/// facts.
pub struct FakeMpcServer {
    outcome: RefCell<Option<FakeMpcOutcome>>,
    observed: RefCell<Option<ToEnclaveTransformationRequest>>,
}

impl FakeMpcServer {
    pub fn returning(outcome: FakeMpcOutcome) -> Self {
        Self {
            outcome: RefCell::new(Some(outcome)),
            observed: RefCell::new(None),
        }
    }

    pub fn returning_success(envelope: EnclaveCiphertextV1) -> Self {
        Self::returning(FakeMpcOutcome::Response(MpcToEnclaveResponse::Success(
            envelope,
        )))
    }

    pub fn observed_request(&self) -> ToEnclaveTransformationRequest {
        self.observed
            .borrow()
            .clone()
            .expect("fake MPC server never received a request")
    }
}

impl MpcToEnclaveSource for FakeMpcServer {
    fn request_to_enclave_transformation(
        &self,
        request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        *self.observed.borrow_mut() = Some(request.clone());
        match self
            .outcome
            .borrow_mut()
            .take()
            .expect("FakeMpcServer outcome already consumed")
        {
            FakeMpcOutcome::Response(response) => Ok(response),
            FakeMpcOutcome::Source(error) => Err(error),
        }
    }
}
