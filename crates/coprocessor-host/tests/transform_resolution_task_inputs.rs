//! Resolution Scheduler tests for issue #39.
//!
//! After the scheduler claims a Resolution Task it must transform every input
//! Handle's `SystemCiphertextV1` into a task-scoped `EnclaveCiphertextV1` by
//! asking MPC for one To-Enclave Transformation per ordered input. The
//! resulting envelopes are passed to the Enclave in the same order as the
//! input Handle Keys and are not persisted by the host.
//!
//! The acceptance criteria from issue #39:
//! - One To-Enclave Transformation per ordered input ciphertext.
//! - Returned `EnclaveCiphertextV1` values preserve input Handle Key order.
//! - `EnclaveCiphertextV1` values are not durably persisted; they are
//!   returned to the caller and dropped after task completion or failure.
//! - Tests cover ordered multi-input transformation, MPC failure, and no
//!   durable retention.

use std::cell::RefCell;

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_handle_graph_core::{
    ChainId, ContractAddress, HandleId, HandleKey, HandleType, OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HostConfig, ResolutionTask, TransformResolutionInputsError,
};
use coprocessor_mpc::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationError,
    ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{
    AttestationDigest, EnclaveAttestationError, EnclaveAttestationMaterial,
    EnclaveAttestationSource, LocalEnclaveAttestationConfig, LocalEnclaveAttestationSource,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN_SEED: u8 = 9;
const DEFAULT_KEY_SEED: u8 = 0xAB;
const DEFAULT_MEASUREMENT_SEED: u8 = 0x33;
const TASK_REQUEST_ID_SEED: u8 = 0x77;

#[test]
fn transform_returns_one_enclave_ciphertext_per_ordered_input_handle() {
    let predicate = handle_key(20);
    let when_true = handle_key(21);
    let when_false = handle_key(22);
    let task = select_task(predicate, when_true, when_false);

    let server = ProgrammableMpcServer::with_successes(vec![
        enclave_envelope_for(predicate, 0xC0),
        enclave_envelope_for(when_true, 0xC1),
        enclave_envelope_for(when_false, 0xC2),
    ]);

    let host = host();
    let attestation = local_attestation_source();

    let outputs = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect("ordered transformation must succeed");

    assert_eq!(
        outputs,
        vec![
            enclave_envelope_for(predicate, 0xC0),
            enclave_envelope_for(when_true, 0xC1),
            enclave_envelope_for(when_false, 0xC2),
        ],
        "EnclaveCiphertextV1 values must be returned in the same order as input Handle Keys",
    );

    let requests = server.observed_requests();
    assert_eq!(
        requests.len(),
        3,
        "scheduler must ask MPC for one To-Enclave Transformation per input",
    );
    let observed_handle_ids: Vec<_> = requests.iter().map(|r| r.handle_id).collect();
    assert_eq!(
        observed_handle_ids,
        vec![
            cbinding::HandleId(predicate.handle_id.0),
            cbinding::HandleId(when_true.handle_id.0),
            cbinding::HandleId(when_false.handle_id.0),
        ],
        "MPC must see input Handle Ids in input order",
    );
}

#[test]
fn transform_forwards_task_scoped_request_facts_to_each_mpc_call() {
    let a = handle_key(1);
    let b = handle_key(2);
    let task = add_task(handle_key(10), a, b);

    let server = ProgrammableMpcServer::with_successes(vec![
        enclave_envelope_for(a, 0xC0),
        enclave_envelope_for(b, 0xC1),
    ]);
    let host = host();
    let attestation = local_attestation_source();

    let _ = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect("transformation must succeed");

    let requests = server.observed_requests();
    assert_ne!(
        requests[0].request_id, requests[1].request_id,
        "each input transformation must have a deterministic per-input RequestId",
    );
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.chain_id, ChainId(DEFAULT_CHAIN));
        assert_eq!(
            request.enclave_public_key,
            attestation_material().enclave_public_key
        );
        assert_eq!(
            request.enclave_measurement,
            attestation_material().enclave_measurement
        );
        assert_eq!(request.attestation, attestation_material().attestation);
        let expected_input = if index == 0 { a } else { b };
        assert_eq!(
            request.handle_id,
            cbinding::HandleId(expected_input.handle_id.0)
        );
        let expected_envelope =
            EnvelopeSystemCiphertextV1::decode(&task.input_system_ciphertexts[index].0)
                .expect("test fixture envelope must decode");
        assert_eq!(request.system_ciphertext, expected_envelope);
    }
}

#[test]
fn transform_derives_stable_request_ids_for_the_same_claimed_task() {
    let a = handle_key(1);
    let b = handle_key(2);
    let task = add_task(handle_key(10), a, b);

    let server = ProgrammableMpcServer::with_successes(vec![
        enclave_envelope_for(a, 0xC0),
        enclave_envelope_for(b, 0xC1),
    ]);
    let host = host();
    let attestation = local_attestation_source();

    let _ = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect("first transformation must succeed");
    let first_request_ids: Vec<_> = server
        .observed_requests()
        .iter()
        .map(|request| request.request_id)
        .collect();

    server.queue_successes(vec![
        enclave_envelope_for(a, 0xC0),
        enclave_envelope_for(b, 0xC1),
    ]);
    let _ = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect("second transformation must succeed");
    let all_requests = server.observed_requests();
    let second_request_ids: Vec<_> = all_requests[2..]
        .iter()
        .map(|request| request.request_id)
        .collect();

    assert_eq!(
        second_request_ids, first_request_ids,
        "the same claimed task must derive stable per-input RequestIds",
    );
}

#[test]
fn transform_short_circuits_on_first_mpc_failure_and_reports_input_index() {
    let a = handle_key(1);
    let b = handle_key(2);
    let task = add_task(handle_key(10), a, b);

    let server = ProgrammableMpcServer::with_outcomes(vec![
        FakeMpcOutcome::Response(MpcToEnclaveResponse::Success(enclave_envelope_for(a, 0xC0))),
        FakeMpcOutcome::Response(MpcToEnclaveResponse::Unauthorized),
    ]);

    let host = host();
    let attestation = local_attestation_source();

    let err = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect_err("an MPC failure on any input must fail the whole transformation");

    assert_eq!(
        err,
        TransformResolutionInputsError::MpcTransformationFailed {
            input_index: 1,
            error: ToEnclaveTransformationError::Unauthorized,
        },
    );
    assert_eq!(
        server.observed_requests().len(),
        2,
        "transform stops after the failing input - no later inputs are requested",
    );
}

#[test]
fn transform_surfaces_transport_unavailable_with_detail() {
    let a = handle_key(1);
    let b = handle_key(2);
    let task = add_task(handle_key(10), a, b);

    let server = ProgrammableMpcServer::with_outcomes(vec![FakeMpcOutcome::SourceError(
        MpcSourceError::Unavailable {
            detail: "mpc endpoint timed out".to_string(),
        },
    )]);

    let host = host();
    let attestation = local_attestation_source();

    let err = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect_err("transport failures must short-circuit the transformation");

    assert_eq!(
        err,
        TransformResolutionInputsError::MpcTransformationFailed {
            input_index: 0,
            error: ToEnclaveTransformationError::Unavailable {
                detail: "mpc endpoint timed out".to_string(),
            },
        },
    );
}

#[test]
fn transform_fails_before_mpc_when_attestation_material_is_unavailable() {
    let a = handle_key(1);
    let b = handle_key(2);
    let task = add_task(handle_key(10), a, b);

    let server = ProgrammableMpcServer::with_successes(vec![
        enclave_envelope_for(a, 0xC0),
        enclave_envelope_for(b, 0xC1),
    ]);
    let host = host();
    let attestation = FailingAttestationSource {
        error: EnclaveAttestationError::BackendUnavailable {
            detail: "local attestation socket unavailable".to_string(),
        },
    };

    let err = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect_err("attestation failures must fail the whole transformation");

    assert_eq!(
        err,
        TransformResolutionInputsError::EnclaveAttestationUnavailable {
            error: EnclaveAttestationError::BackendUnavailable {
                detail: "local attestation socket unavailable".to_string(),
            },
        },
    );
    assert!(
        server.observed_requests().is_empty(),
        "MPC must not be called without task-scoped Enclave attestation material",
    );
}

#[test]
fn transform_returns_decode_error_for_malformed_input_system_ciphertext() {
    let a = handle_key(1);
    let b = handle_key(2);
    let mut task = add_task(handle_key(10), a, b);
    task.input_system_ciphertexts[1] = SystemCiphertextV1(vec![0xFF, 0xFE, 0xFD]);

    let server = ProgrammableMpcServer::with_successes(vec![enclave_envelope_for(a, 0xC0)]);

    let host = host();
    let attestation = local_attestation_source();

    let err = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .expect_err("malformed input envelope must fail the transformation");

    match err {
        TransformResolutionInputsError::MalformedSystemCiphertext { input_index, .. } => {
            assert_eq!(input_index, 1);
        }
        other => panic!("expected MalformedSystemCiphertext, got {other:?}"),
    }
    assert_eq!(
        server.observed_requests().len(),
        1,
        "the second input must not reach MPC once decoding fails",
    );
}

#[test]
fn transform_is_pure_and_does_not_retain_enclave_ciphertexts_after_drop() {
    // Pure means: the function returns the EnclaveCiphertextV1 values to the
    // caller and the program retains no other reference. After the returned
    // Vec is dropped, no other component can recover the values. We pin this
    // by exercising it in a scope where the result is dropped, then asserting
    // the fake MPC source is the only remaining producer of the same envelope
    // bytes (and producing them again requires a fresh MPC call).
    let a = handle_key(1);
    let b = handle_key(2);
    let task = add_task(handle_key(10), a, b);
    let host = host();
    let attestation = local_attestation_source();

    let server = ProgrammableMpcServer::with_successes(vec![
        enclave_envelope_for(a, 0xC0),
        enclave_envelope_for(b, 0xC1),
    ]);

    {
        let outputs = host
            .transform_resolution_task_inputs(&task, &server, &attestation)
            .unwrap();
        assert_eq!(outputs.len(), 2);
        // outputs goes out of scope here; the function owns no state to
        // resurrect them later.
    }

    // A second tick must round-trip to MPC again: there is no host-side cache
    // of EnclaveCiphertextV1 that would let the scheduler skip the call.
    server.queue_successes(vec![
        enclave_envelope_for(a, 0xC0),
        enclave_envelope_for(b, 0xC1),
    ]);
    let _ = host
        .transform_resolution_task_inputs(&task, &server, &attestation)
        .unwrap();

    assert_eq!(
        server.observed_requests().len(),
        4,
        "no durable EnclaveCiphertextV1 retention means every tick re-asks MPC",
    );
}

// ---------- fixtures ----------

fn add_task(output: HandleKey, a: HandleKey, b: HandleKey) -> ResolutionTask {
    ResolutionTask {
        output_handle_key: output,
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![a, b],
        input_system_ciphertexts: vec![
            system_ciphertext_for(a, "suint256"),
            system_ciphertext_for(b, "suint256"),
        ],
    }
}

fn select_task(
    predicate: HandleKey,
    when_true: HandleKey,
    when_false: HandleKey,
) -> ResolutionTask {
    ResolutionTask {
        output_handle_key: handle_key(99),
        operation_code: OperationCode::Select,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![predicate, when_true, when_false],
        input_system_ciphertexts: vec![
            system_ciphertext_for(predicate, "sbool"),
            system_ciphertext_for(when_true, "suint256"),
            system_ciphertext_for(when_false, "suint256"),
        ],
    }
}

fn system_ciphertext_for(handle_key: HandleKey, type_tag: &str) -> SystemCiphertextV1 {
    let aad = SystemHandleAadV1 {
        version: 1,
        chain_id: handle_key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN_SEED; 32]),
        handle_id: cbinding::HandleId(handle_key.handle_id.0),
        type_tag: type_tag.to_string(),
        key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
    }
    .encode();
    let envelope = EnvelopeSystemCiphertextV1 {
        version: 1,
        aad,
        wrapped_key: vec![0xAA; 32],
        ciphertext: vec![0xBB; 64],
    };
    SystemCiphertextV1(envelope.encode())
}

fn enclave_envelope_for(handle_key: HandleKey, payload_seed: u8) -> EnclaveCiphertextV1 {
    let aad = EnclaveAadV1 {
        version: 1,
        chain_id: handle_key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN_SEED; 32]),
        request_id: cbinding::RequestId([TASK_REQUEST_ID_SEED; 32]),
        handle_id: cbinding::HandleId(handle_key.handle_id.0),
        type_tag: "suint256".to_string(),
        attestation_digest: AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
    }
    .encode();
    EnclaveCiphertextV1 {
        version: 1,
        aad,
        wrapped_key: vec![payload_seed; 32],
        ciphertext: vec![payload_seed; 64],
    }
}

fn attestation_material() -> EnclaveAttestationMaterial {
    EnclaveAttestationMaterial {
        enclave_public_key: vec![0x44; 48],
        enclave_measurement: AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        attestation: vec![0x55; 96],
    }
}

fn local_attestation_source() -> LocalEnclaveAttestationSource {
    let material = attestation_material();
    LocalEnclaveAttestationSource::new(LocalEnclaveAttestationConfig {
        enclave_public_key: material.enclave_public_key,
        enclave_measurement: material.enclave_measurement,
        attestation: material.attestation,
    })
}

fn host() -> CoprocessorHost {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host
}

fn handle_key(seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(DEFAULT_CHAIN),
        contract_address: ContractAddress([DEFAULT_CONTRACT_SEED; 20]),
        handle_id: HandleId([seed; 32]),
    }
}

// ---------- fake MPC source ----------

enum FakeMpcOutcome {
    Response(MpcToEnclaveResponse),
    SourceError(MpcSourceError),
}

struct ProgrammableMpcServer {
    queued: RefCell<Vec<FakeMpcOutcome>>,
    observed: RefCell<Vec<ToEnclaveTransformationRequest>>,
}

impl ProgrammableMpcServer {
    fn with_outcomes(outcomes: Vec<FakeMpcOutcome>) -> Self {
        Self {
            queued: RefCell::new(outcomes),
            observed: RefCell::new(Vec::new()),
        }
    }

    fn with_successes(envelopes: Vec<EnclaveCiphertextV1>) -> Self {
        Self::with_outcomes(
            envelopes
                .into_iter()
                .map(|envelope| FakeMpcOutcome::Response(MpcToEnclaveResponse::Success(envelope)))
                .collect(),
        )
    }

    fn queue_successes(&self, envelopes: Vec<EnclaveCiphertextV1>) {
        let mut queued = self.queued.borrow_mut();
        for envelope in envelopes {
            queued.push(FakeMpcOutcome::Response(MpcToEnclaveResponse::Success(
                envelope,
            )));
        }
    }

    fn observed_requests(&self) -> Vec<ToEnclaveTransformationRequest> {
        self.observed.borrow().clone()
    }
}

impl MpcToEnclaveSource for ProgrammableMpcServer {
    fn request_to_enclave_transformation(
        &self,
        request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        self.observed.borrow_mut().push(request.clone());
        let outcome = self
            .queued
            .borrow_mut()
            .drain(..1)
            .next()
            .expect("ProgrammableMpcServer ran out of programmed outcomes");
        match outcome {
            FakeMpcOutcome::Response(response) => Ok(response),
            FakeMpcOutcome::SourceError(error) => Err(error),
        }
    }
}

struct FailingAttestationSource {
    error: EnclaveAttestationError,
}

impl EnclaveAttestationSource for FailingAttestationSource {
    fn current_attestation_material(
        &self,
    ) -> Result<EnclaveAttestationMaterial, EnclaveAttestationError> {
        Err(self.error.clone())
    }
}
