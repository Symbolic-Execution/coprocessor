//! MPC To-Enclave Transformation client used by the Coprocessor Host.
//!
//! When a Resolution Task is ready, the host asks MPC to transform each input
//! [`SystemCiphertextV1`] into an [`EnclaveCiphertextV1`] bound to an attested
//! Enclave key. This crate owns three concerns:
//!
//! 1. The [`ToEnclaveTransformationRequest`] value object — the spec fields
//!    the host must forward to MPC (request id, chain id, handle id, enclave
//!    public key and approved measurement, attestation evidence, and the
//!    input [`SystemCiphertextV1`]).
//! 2. The [`MpcToEnclaveSource`] seam — an indirection point so tests use a
//!    fake MPC server and a later slice can wire an HTTP-backed
//!    implementation when the host runtime is chosen.
//! 3. Mapping wire-level outcomes to a stable
//!    [`ToEnclaveTransformationError`] surface so a transient transport
//!    failure, a malformed reply, an authorization refusal, an invalid
//!    binding, and an invalid attestation are each their own variant.
//!
//! Privacy: the request carries opaque enclave key, attestation, and
//! ciphertext bytes; the response carries an opaque [`EnclaveCiphertextV1`].
//! No variant of [`ToEnclaveTransformationError`] embeds any of those bytes,
//! so logging an error never leaks key material or ciphertext.

pub use coprocessor_ciphertext_binding::{
    AttestationDigest, EnclaveCiphertextV1, HandleId, RequestId, SystemCiphertextV1,
};
pub use coprocessor_handle_graph_core::ChainId;

/// One MPC To-Enclave Transformation request. The host populates this from
/// the [`ResolutionTask`](coprocessor_ciphertext_binding) facts together with
/// the attested Enclave key, then asks the [`MpcToEnclaveSource`] to perform
/// the transformation.
///
/// `enclave_public_key` and `attestation` are opaque byte payloads the host
/// must forward but never inspect. `enclave_measurement` is the approved
/// Enclave Measurement digest MPC checks the attestation against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToEnclaveTransformationRequest {
    pub request_id: RequestId,
    pub chain_id: ChainId,
    pub handle_id: HandleId,
    pub enclave_public_key: Vec<u8>,
    pub enclave_measurement: AttestationDigest,
    pub attestation: Vec<u8>,
    pub system_ciphertext: SystemCiphertextV1,
}

/// Protocol-level response from an MPC backend.
///
/// The seam exists at this level (not at raw bytes) so a backend
/// implementation can translate its wire shape — HTTP status, gRPC status,
/// or fake — into the same four-variant contract before reaching the
/// client. The [`Success`](MpcToEnclaveResponse::Success) variant carries
/// the typed [`EnclaveCiphertextV1`] so the client never has to re-parse
/// envelope bytes itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcToEnclaveResponse {
    /// MPC accepted the request and produced an [`EnclaveCiphertextV1`]
    /// bound for the attested Enclave key.
    Success(EnclaveCiphertextV1),
    /// MPC rejected the request because the caller's authorization
    /// (transport credentials, signing key, or rate ceiling) was invalid.
    Unauthorized,
    /// MPC rejected the request because the [`SystemCiphertextV1`]'s AAD
    /// binding did not match the request facts (chain id, domain id, handle
    /// id, type tag, or key id).
    InvalidBinding,
    /// MPC rejected the request because the Attestation did not bind the
    /// supplied enclave public key to an approved Enclave Measurement.
    InvalidAttestation,
}

/// Reasons the [`MpcToEnclaveSource`] seam itself failed before producing a
/// protocol response. Distinct from the response variants so the client can
/// surface a network failure separately from an MPC protocol decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcSourceError {
    /// The MPC endpoint was unreachable or returned a transient error.
    /// `detail` is non-secret diagnostic context the host may log.
    Unavailable { detail: String },
    /// The MPC endpoint replied but the reply could not be parsed as any
    /// known protocol response.
    MalformedResponse,
}

/// Seam for talking to an MPC backend. Implementations carry their own
/// transport, authentication, and serialization; this trait only commits to
/// the typed protocol contract.
pub trait MpcToEnclaveSource {
    fn request_to_enclave_transformation(
        &self,
        request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError>;
}

/// Combined error surface returned by [`request_to_enclave_transformation`].
///
/// The five variants are the spec-mandated failure dimensions: transient
/// backend availability, malformed responses, authorization refusal, invalid
/// ciphertext binding, and invalid attestation. They stay distinct so the
/// host can map each to its own response code and retry policy without
/// re-parsing diagnostic strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToEnclaveTransformationError {
    /// Transient transport failure. The host may retry while its retry
    /// policy allows it.
    Unavailable { detail: String },
    /// MPC replied but the reply did not parse as a known response.
    MalformedResponse,
    /// MPC rejected the request because the caller's authorization was
    /// invalid.
    Unauthorized,
    /// MPC rejected the request because the [`SystemCiphertextV1`] AAD did
    /// not match the request facts.
    InvalidBinding,
    /// MPC rejected the request because the Attestation did not bind the
    /// enclave public key to an approved Enclave Measurement.
    InvalidAttestation,
}

/// Ask MPC to transform the request's [`SystemCiphertextV1`] into an
/// [`EnclaveCiphertextV1`] bound to the attested Enclave key.
///
/// On success, returns the [`EnclaveCiphertextV1`] the host hands to the
/// Enclave runtime as task-scoped input material. On failure, returns one
/// of the five spec-mandated [`ToEnclaveTransformationError`] variants.
pub fn request_to_enclave_transformation(
    source: &dyn MpcToEnclaveSource,
    request: &ToEnclaveTransformationRequest,
) -> Result<EnclaveCiphertextV1, ToEnclaveTransformationError> {
    match source.request_to_enclave_transformation(request) {
        Ok(MpcToEnclaveResponse::Success(envelope)) => Ok(envelope),
        Ok(MpcToEnclaveResponse::Unauthorized) => Err(ToEnclaveTransformationError::Unauthorized),
        Ok(MpcToEnclaveResponse::InvalidBinding) => {
            Err(ToEnclaveTransformationError::InvalidBinding)
        }
        Ok(MpcToEnclaveResponse::InvalidAttestation) => {
            Err(ToEnclaveTransformationError::InvalidAttestation)
        }
        Err(MpcSourceError::Unavailable { detail }) => {
            Err(ToEnclaveTransformationError::Unavailable { detail })
        }
        Err(MpcSourceError::MalformedResponse) => {
            Err(ToEnclaveTransformationError::MalformedResponse)
        }
    }
}
