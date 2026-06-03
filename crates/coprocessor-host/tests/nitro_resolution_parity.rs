//! Nitro Enclave adapter parity and wiring tests for issue #45.
//!
//! Verifies that production Nitro-mode Resolution produces identical
//! scheduler-facing outcomes to local-mode Resolution, that the Nitro adapter
//! is correctly wired through the HostConfig factory, and that misconfiguration
//! or adapter rejection paths map cleanly to the existing failure classification.
//!
//! Non-goals: real NSM transport, real cryptography, disclosure flows.

use std::cell::RefCell;

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_enclave_runtime::{AttestationDigest, FakeEnclaveRuntime};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleType, ImportedHandle, MaterializationReceipt, OperationCode,
    SystemCiphertextV1,
};
use coprocessor_host::{
    ChainEventSource, ChainView, ChainViewPoll, CoprocessorHost, EnclaveAttestationConfig,
    HandleStateFailureCategory, HandleStateView, HostConfig, HostConfigError, HostStartError,
};
use coprocessor_mpc_client::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{
    AttestationDigest as NitroAttestationDigest, LocalEnclaveAttestationConfig,
    NitroAdapterConfig, NitroAttestationDoc, NitroAttestationDocSource, NitroSourceError,
};

// Shared measurement value used by both Local and Nitro paths in parity tests.
const SHARED_MEASUREMENT: NitroAttestationDigest = NitroAttestationDigest([0xA2; 32]);
const SHARED_PUBLIC_KEY: &[u8] = &[0xA1; 48];
const SHARED_ATTESTATION: &[u8] = &[0xA3; 96];

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 0xCC;
const DEFAULT_DOMAIN: u8 = 0xDD;
const DEFAULT_KEY_SEED: u8 = 0xEE;

// ---------- parity tests ----------

/// Both Local and Nitro sources backed by identical material produce identical
/// DerivedHandleReceiptView (operation_code, output key, input keys, attestation_digest)
/// and both handle states reach Ready.
#[test]
fn local_and_nitro_produce_identical_receipt() {
    let local_result = run_add_resolution_with_local_source();
    let nitro_result = run_add_resolution_with_nitro_source();

    assert!(
        matches!(local_result.view, HandleStateView::Ready { .. }),
        "local path must reach Ready, got {:?}",
        local_result.view
    );
    assert!(
        matches!(nitro_result.view, HandleStateView::Ready { .. }),
        "nitro path must reach Ready, got {:?}",
        nitro_result.view
    );

    let local_receipt = extract_derived_receipt(&local_result.view);
    let nitro_receipt = extract_derived_receipt(&nitro_result.view);

    assert_eq!(
        local_receipt.operation_code, nitro_receipt.operation_code,
        "operation_code must match"
    );
    assert_eq!(
        local_receipt.output_handle_key, nitro_receipt.output_handle_key,
        "output_handle_key must match"
    );
    assert_eq!(
        local_receipt.input_handle_keys, nitro_receipt.input_handle_keys,
        "input_handle_keys ordering must match"
    );
    assert_eq!(
        local_receipt.attestation_digest, nitro_receipt.attestation_digest,
        "attestation_digest must match — both sources use SHARED_MEASUREMENT"
    );
    assert_eq!(
        local_receipt.attestation_digest,
        AttestationDigest(SHARED_MEASUREMENT.0),
        "attestation_digest must equal SHARED_MEASUREMENT"
    );
}

/// The Nitro path receipt's attestation_digest equals the adapter's
/// approved_enclave_measurement (the PCR0 of the attested document).
#[test]
fn nitro_receipt_attestation_digest_equals_approved_measurement() {
    let nitro_result = run_add_resolution_with_nitro_source();

    assert!(
        matches!(nitro_result.view, HandleStateView::Ready { .. }),
        "Nitro path must be Ready, got {:?}",
        nitro_result.view
    );

    let receipt = extract_derived_receipt(&nitro_result.view);
    assert_eq!(
        receipt.attestation_digest,
        AttestationDigest(SHARED_MEASUREMENT.0),
        "receipt attestation_digest must equal the Nitro adapter's approved measurement"
    );
}

// ---------- production wiring: factory tests ----------

/// A host built from Nitro config obtains attestation material from the
/// NitroEnclaveAdapter before MPC transformation. The MPC request carries the
/// Nitro adapter's measurement.
#[test]
fn nitro_factory_wires_adapter_measurement_to_mpc_request() {
    let config =
        HostConfig::for_production_nitro(SHARED_MEASUREMENT, SHARED_PUBLIC_KEY.len());

    let fake_doc = FakeNitroDocSource::matching();
    let attestation_source = config
        .build_nitro_attestation_source(fake_doc)
        .expect("valid Nitro config must build attestation source");

    let mut host = CoprocessorHost::new(config);
    host.start().expect("valid Nitro config must start");

    let (a, b, _) = setup_add_scenario(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = &tasks[0];

    let recording_mpc = RecordingMpcServer::new(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(
        task,
        &recording_mpc,
        attestation_source.as_ref(),
        &enclave,
    );

    assert!(
        matches!(view, HandleStateView::Ready { .. }),
        "Nitro factory path must reach Ready, got {:?}",
        view
    );

    // Assert MPC received the Nitro adapter's measurement in every request.
    for request in recording_mpc.recorded_requests() {
        assert_eq!(
            request.enclave_measurement,
            AttestationDigest(SHARED_MEASUREMENT.0),
            "every MPC request must carry the Nitro adapter's measurement"
        );
        assert_eq!(
            request.enclave_public_key,
            SHARED_PUBLIC_KEY,
            "every MPC request must carry the Nitro adapter's public key"
        );
        assert_eq!(
            request.attestation,
            SHARED_ATTESTATION,
            "every MPC request must carry the Nitro adapter's attestation evidence"
        );
    }
}

// ---------- misconfiguration: fails host wiring fast ----------

/// Zero expected_public_key_len in Nitro config must surface
/// InvalidEnclaveAttestationConfig at host start.
#[test]
fn zero_expected_public_key_len_fails_host_start() {
    let config = HostConfig {
        enclave_attestation: EnclaveAttestationConfig::Nitro(NitroAdapterConfig {
            approved_enclave_measurement: SHARED_MEASUREMENT,
            expected_public_key_len: 0,
        }),
        ..HostConfig::for_local_development()
    };

    let mut host = CoprocessorHost::new(config.clone());
    let err = host.start().expect_err("zero key len must fail host start");

    assert!(
        matches!(
            err,
            HostStartError::InvalidConfig(HostConfigError::InvalidEnclaveAttestationConfig { .. })
        ),
        "must be InvalidEnclaveAttestationConfig, got {:?}",
        err
    );

    // validate_config must also surface the error.
    let err = CoprocessorHost::validate_config(&config).expect_err("validate must fail");
    assert!(
        matches!(err, HostConfigError::InvalidEnclaveAttestationConfig { .. }),
        "validate_config must return InvalidEnclaveAttestationConfig, got {:?}",
        err
    );
}

/// All-zero approved_enclave_measurement must fail host start.
#[test]
fn all_zero_approved_measurement_fails_host_start() {
    let config = HostConfig {
        enclave_attestation: EnclaveAttestationConfig::Nitro(NitroAdapterConfig {
            approved_enclave_measurement: NitroAttestationDigest([0u8; 32]),
            expected_public_key_len: 48,
        }),
        ..HostConfig::for_local_development()
    };

    let mut host = CoprocessorHost::new(config.clone());
    let err = host.start().expect_err("all-zero measurement must fail host start");

    assert!(
        matches!(
            err,
            HostStartError::InvalidConfig(HostConfigError::InvalidEnclaveAttestationConfig { .. })
        ),
        "must be InvalidEnclaveAttestationConfig, got {:?}",
        err
    );
}

/// build_nitro_attestation_source with a valid Nitro config succeeds.
#[test]
fn build_nitro_source_succeeds_for_valid_nitro_config() {
    let config = HostConfig::for_production_nitro(SHARED_MEASUREMENT, SHARED_PUBLIC_KEY.len());
    let result = config.build_nitro_attestation_source(FakeNitroDocSource::matching());
    assert!(result.is_ok(), "valid Nitro config must build source");
}

/// build_nitro_attestation_source with zero key len returns InvalidEnclaveAttestationConfig.
#[test]
fn build_nitro_source_rejects_zero_key_len() {
    let config = HostConfig {
        enclave_attestation: EnclaveAttestationConfig::Nitro(NitroAdapterConfig {
            approved_enclave_measurement: SHARED_MEASUREMENT,
            expected_public_key_len: 0,
        }),
        ..HostConfig::for_local_development()
    };
    let result = config.build_nitro_attestation_source(FakeNitroDocSource::matching());
    assert!(result.is_err(), "zero key len must fail");
    let err = result.err().unwrap();
    assert!(
        matches!(err, HostStartError::InvalidEnclaveAttestationConfig(_)),
        "must be InvalidEnclaveAttestationConfig, got {:?}",
        err
    );
}

/// build_local_attestation_source on a Local config succeeds.
#[test]
fn build_local_source_succeeds_for_local_config() {
    let config = HostConfig::for_local_development();
    let result = config.build_local_attestation_source();
    assert!(result.is_ok(), "Local config must build local source");
}

/// build_nitro_attestation_source on a Local config returns EnclaveAttestationModeMismatch.
#[test]
fn build_nitro_source_on_local_config_returns_mode_mismatch() {
    let config = HostConfig::for_local_development();
    let result = config.build_nitro_attestation_source(FakeNitroDocSource::matching());
    assert!(result.is_err(), "must fail for Local config");
    let err = result.err().unwrap();
    assert!(
        matches!(err, HostStartError::EnclaveAttestationModeMismatch),
        "must be EnclaveAttestationModeMismatch, got {:?}",
        err
    );
}

/// build_local_attestation_source on a Nitro config returns EnclaveAttestationModeMismatch.
#[test]
fn build_local_source_on_nitro_config_returns_mode_mismatch() {
    let config = HostConfig::for_production_nitro(SHARED_MEASUREMENT, SHARED_PUBLIC_KEY.len());
    let result = config.build_local_attestation_source();
    assert!(result.is_err(), "must fail for Nitro config");
    let err = result.err().unwrap();
    assert!(
        matches!(err, HostStartError::EnclaveAttestationModeMismatch),
        "must be EnclaveAttestationModeMismatch, got {:?}",
        err
    );
}

// ---------- Nitro adapter rejection paths ----------

/// PCR0 mismatch in the attestation doc is a terminal failure: the handle
/// transitions to Failed (EnclaveExecutionFailure or MpcTransformationFailure
/// depending on where the error is classified).
#[test]
fn pcr0_mismatch_is_terminal_failure() {
    let mut host = running_host_with_nitro(SHARED_MEASUREMENT, SHARED_PUBLIC_KEY.len());
    let (_, _, derived) = setup_add_scenario(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = &tasks[0];

    // Wrong PCR0 in the doc -> MeasurementMismatch -> Terminal
    let bad_doc_source = FakeNitroDocSource::with_pcr0(NitroAttestationDigest([0xFF; 32]));
    let nitro_source = NitroEnclaveAdapter::new(
        NitroAdapterConfig {
            approved_enclave_measurement: SHARED_MEASUREMENT,
            expected_public_key_len: SHARED_PUBLIC_KEY.len(),
        },
        bad_doc_source,
    )
    .expect("valid config");

    let mpc_server = ProgrammableMpcServer::empty();
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &nitro_source, &enclave);

    assert!(
        matches!(
            view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::MpcTransformationFailure,
                ..
            }
        ),
        "PCR0 mismatch must produce terminal MpcTransformationFailure, got {:?}",
        view
    );
    assert!(
        !host.is_resolution_task_claimed(&derived),
        "claim must be released after terminal failure"
    );
    assert_eq!(
        host.claim_resolution_tasks().len(),
        0,
        "Failed handle must not re-enter readiness"
    );
}

/// Wrong public key length is a terminal failure.
#[test]
fn wrong_public_key_length_is_terminal_failure() {
    let mut host = running_host_with_nitro(SHARED_MEASUREMENT, SHARED_PUBLIC_KEY.len());
    let (_, _, derived) = setup_add_scenario(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];

    // Doc with wrong-length public key -> MalformedAttestation -> Terminal
    let bad_doc_source = FakeNitroDocSource::with_public_key(vec![0xBB; 32]); // wrong length
    let nitro_source = NitroEnclaveAdapter::new(
        NitroAdapterConfig {
            approved_enclave_measurement: SHARED_MEASUREMENT,
            expected_public_key_len: SHARED_PUBLIC_KEY.len(), // 48, not 32
        },
        bad_doc_source,
    )
    .expect("valid config");

    let mpc_server = ProgrammableMpcServer::empty();
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &nitro_source, &enclave);

    assert!(
        matches!(
            view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::MpcTransformationFailure,
                ..
            }
        ),
        "wrong key length must produce terminal MpcTransformationFailure, got {:?}",
        view
    );
    assert!(!host.is_resolution_task_claimed(&derived));
}

/// NSM unavailable is retryable while budget remains: handle stays Pending.
#[test]
fn nsm_unavailable_is_retryable_while_budget_remains() {
    let mut host = running_host_with_nitro(SHARED_MEASUREMENT, SHARED_PUBLIC_KEY.len());
    let (_, _, derived) = setup_add_scenario(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];

    // NSM Unavailable -> BackendUnavailable -> Retryable
    let unavailable_source = FakeNitroDocSource::unavailable();
    let nitro_source = NitroEnclaveAdapter::new(
        NitroAdapterConfig {
            approved_enclave_measurement: SHARED_MEASUREMENT,
            expected_public_key_len: SHARED_PUBLIC_KEY.len(),
        },
        unavailable_source,
    )
    .expect("valid config");

    let mpc_server = ProgrammableMpcServer::empty();
    let enclave = FakeEnclaveRuntime::deterministic();

    // Default max_attempts is 3 so the first retryable failure keeps handle Pending.
    let view = host.resolve_claimed_task(task, &mpc_server, &nitro_source, &enclave);

    assert_eq!(
        view,
        HandleStateView::Pending,
        "NSM unavailable must keep handle Pending while budget remains"
    );
    assert!(
        !host.is_resolution_task_claimed(&derived),
        "claim must be released for re-claim on next tick"
    );
    // Handle still Pending so it remains eligible for re-claim.
    assert_eq!(host.claim_resolution_tasks().len(), 1);
}

/// NSM unavailable exhausts budget and promotes to terminal failure.
#[test]
fn nsm_unavailable_exhausts_budget_and_fails() {
    let config = HostConfig {
        retry_policy: coprocessor_host::RetryPolicy { max_attempts: 1 },
        enclave_attestation: EnclaveAttestationConfig::Nitro(NitroAdapterConfig {
            approved_enclave_measurement: SHARED_MEASUREMENT,
            expected_public_key_len: SHARED_PUBLIC_KEY.len(),
        }),
        ..HostConfig::for_local_development()
    };
    let mut host = CoprocessorHost::new(config);
    host.start().unwrap();

    let (_, _, derived) = setup_add_scenario(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];

    let unavailable_source = FakeNitroDocSource::unavailable();
    let nitro_source = NitroEnclaveAdapter::new(
        NitroAdapterConfig {
            approved_enclave_measurement: SHARED_MEASUREMENT,
            expected_public_key_len: SHARED_PUBLIC_KEY.len(),
        },
        unavailable_source,
    )
    .expect("valid config");

    let mpc_server = ProgrammableMpcServer::empty();
    let enclave = FakeEnclaveRuntime::deterministic();

    // max_attempts=1 means no retries: first failure exhausts budget -> terminal.
    let view = host.resolve_claimed_task(task, &mpc_server, &nitro_source, &enclave);

    assert!(
        matches!(view, HandleStateView::Failed { .. }),
        "NSM unavailable with budget=0 must produce terminal Failed, got {:?}",
        view
    );
    assert!(!host.is_resolution_task_claimed(&derived));
    assert_eq!(host.claim_resolution_tasks().len(), 0);
}

// ---------- helpers ----------

struct ResolutionResult {
    view: HandleStateView,
}

fn run_add_resolution_with_local_source() -> ResolutionResult {
    let config = host_config_with_shared_local_attestation();
    let mut host = running_host_from_config(config.clone());
    let (a, b, _) = setup_add_scenario(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1, "must claim exactly one task");
    let task = &tasks[0];

    let attestation_source = config
        .build_local_attestation_source()
        .expect("shared Local config must build attestation source");
    let mpc_server = ProgrammableMpcServer::new(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, attestation_source.as_ref(), &enclave);
    ResolutionResult { view }
}

fn run_add_resolution_with_nitro_source() -> ResolutionResult {
    let config =
        HostConfig::for_production_nitro(SHARED_MEASUREMENT, SHARED_PUBLIC_KEY.len());
    let mut host = running_host_from_config(config.clone());
    let (a, b, _) = setup_add_scenario(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1, "must claim exactly one task");
    let task = &tasks[0];

    let nitro_source = config
        .build_nitro_attestation_source(FakeNitroDocSource::matching())
        .expect("shared Nitro config must build attestation source");

    let mpc_server = ProgrammableMpcServer::new(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, nitro_source.as_ref(), &enclave);
    ResolutionResult { view }
}

fn running_host_from_config(config: HostConfig) -> CoprocessorHost {
    let mut host = CoprocessorHost::new(config);
    host.start().unwrap();
    host
}

fn running_host_with_nitro(
    measurement: NitroAttestationDigest,
    expected_public_key_len: usize,
) -> CoprocessorHost {
    let config = HostConfig::for_production_nitro(measurement, expected_public_key_len);
    running_host_from_config(config)
}

fn setup_add_scenario(host: &mut CoprocessorHost) -> (HandleKey, HandleKey, HandleKey) {
    let a = handle_key(0x01);
    let b = handle_key(0x02);
    let derived = handle_key(0x10);
    ingest_events(
        host,
        vec![
            imported_event(
                a,
                HandleType::Suint256,
                well_formed_system_ciphertext(a, "suint256"),
                1,
                1,
            ),
            imported_event(
                b,
                HandleType::Suint256,
                well_formed_system_ciphertext(b, "suint256"),
                1,
                2,
            ),
            derived_event(
                derived,
                OperationCode::Add,
                HandleType::Suint256,
                vec![a, b],
                2,
                1,
            ),
        ],
    );
    (a, b, derived)
}

fn host_config_with_shared_local_attestation() -> HostConfig {
    HostConfig {
        enclave_attestation: EnclaveAttestationConfig::Local(LocalEnclaveAttestationConfig {
            enclave_public_key: SHARED_PUBLIC_KEY.to_vec(),
            enclave_measurement: SHARED_MEASUREMENT,
            attestation: SHARED_ATTESTATION.to_vec(),
        }),
        ..HostConfig::for_local_development()
    }
}

fn extract_derived_receipt(view: &HandleStateView) -> coprocessor_host::DerivedHandleReceiptView {
    match view {
        HandleStateView::Ready { derived_receipt, .. } => derived_receipt
            .clone()
            .expect("Derived Handle must have a DerivedHandleReceiptView"),
        other => panic!("expected Ready, got {:?}", other),
    }
}

fn handle_key(seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(DEFAULT_CHAIN),
        contract_address: ContractAddress([DEFAULT_CONTRACT_SEED; 20]),
        handle_id: HandleId([seed; 32]),
    }
}

fn event_ref(block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(DEFAULT_CHAIN),
        block_number,
        block_hash: [0xAA; 32],
        tx_hash: [0xBB; 32],
        log_index,
    }
}

fn well_formed_system_ciphertext(key: HandleKey, type_tag: &str) -> SystemCiphertextV1 {
    let aad = SystemHandleAadV1 {
        version: 1,
        chain_id: key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN; 32]),
        handle_id: cbinding::HandleId(key.handle_id.0),
        type_tag: type_tag.to_string(),
        key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
    }
    .encode();
    SystemCiphertextV1(
        EnvelopeSystemCiphertextV1 {
            version: 1,
            aad,
            wrapped_key: vec![0xAA; 32],
            ciphertext: vec![0xBB; 64],
        }
        .encode(),
    )
}

fn fake_enclave_ciphertext(key: HandleKey, payload_seed: u8) -> EnclaveCiphertextV1 {
    let aad = EnclaveAadV1 {
        version: 1,
        chain_id: key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN; 32]),
        request_id: cbinding::RequestId([0x88; 32]),
        handle_id: cbinding::HandleId(key.handle_id.0),
        type_tag: "suint256".to_string(),
        attestation_digest: AttestationDigest(SHARED_MEASUREMENT.0),
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

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    system_ciphertext: SystemCiphertextV1,
    block_number: u64,
    log_index: u32,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key,
        handle_type,
        system_ciphertext,
        materialization_receipt: MaterializationReceipt(vec![0x01]),
        event_ref: event_ref(block_number, log_index),
    })
}

fn derived_event(
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    block_number: u64,
    log_index: u32,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key,
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref: event_ref(block_number, log_index),
    })
}

fn ingest_events(host: &mut CoprocessorHost, events: Vec<ChainEvent>) {
    let mut source = FixedChainSource::new(events);
    host.ingest_chain_events(&mut source);
}

// ---------- fake Nitro doc source ----------

use coprocessor_nitro_enclave::NitroEnclaveAdapter;

/// A configurable fake NitroAttestationDocSource for testing adapter behavior.
struct FakeNitroDocSource {
    result: Result<NitroAttestationDoc, NitroSourceError>,
}

impl FakeNitroDocSource {
    /// Returns a document whose PCR0, public key, and bytes all match SHARED_*.
    fn matching() -> Self {
        Self {
            result: Ok(NitroAttestationDoc {
                pcr0: SHARED_MEASUREMENT,
                enclave_public_key: SHARED_PUBLIC_KEY.to_vec(),
                document_bytes: SHARED_ATTESTATION.to_vec(),
            }),
        }
    }

    /// Returns a document with a different PCR0 to trigger MeasurementMismatch.
    fn with_pcr0(pcr0: NitroAttestationDigest) -> Self {
        Self {
            result: Ok(NitroAttestationDoc {
                pcr0,
                enclave_public_key: SHARED_PUBLIC_KEY.to_vec(),
                document_bytes: SHARED_ATTESTATION.to_vec(),
            }),
        }
    }

    /// Returns a document with a different-length public key to trigger MalformedAttestation.
    fn with_public_key(enclave_public_key: Vec<u8>) -> Self {
        Self {
            result: Ok(NitroAttestationDoc {
                pcr0: SHARED_MEASUREMENT,
                enclave_public_key,
                document_bytes: SHARED_ATTESTATION.to_vec(),
            }),
        }
    }

    /// Returns an NSM Unavailable error.
    fn unavailable() -> Self {
        Self {
            result: Err(NitroSourceError::Unavailable {
                detail: "test: nsm unavailable".to_string(),
            }),
        }
    }
}

impl NitroAttestationDocSource for FakeNitroDocSource {
    fn fetch_attestation_doc(&self) -> Result<NitroAttestationDoc, NitroSourceError> {
        self.result.clone()
    }
}

// ---------- fake MPC server ----------

struct ProgrammableMpcServer {
    queued: RefCell<Vec<EnclaveCiphertextV1>>,
}

impl ProgrammableMpcServer {
    fn new(envelopes: Vec<EnclaveCiphertextV1>) -> Self {
        Self {
            queued: RefCell::new(envelopes),
        }
    }

    fn empty() -> Self {
        Self::new(vec![])
    }
}

impl MpcToEnclaveSource for ProgrammableMpcServer {
    fn request_to_enclave_transformation(
        &self,
        _request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        let next = self
            .queued
            .borrow_mut()
            .drain(..1)
            .next()
            .expect("ProgrammableMpcServer ran out of queued envelopes");
        Ok(MpcToEnclaveResponse::Success(next))
    }
}

/// Records all ToEnclaveTransformationRequest values before forwarding.
struct RecordingMpcServer {
    inner: ProgrammableMpcServer,
    requests: RefCell<Vec<ToEnclaveTransformationRequest>>,
}

impl RecordingMpcServer {
    fn new(envelopes: Vec<EnclaveCiphertextV1>) -> Self {
        Self {
            inner: ProgrammableMpcServer::new(envelopes),
            requests: RefCell::new(Vec::new()),
        }
    }

    fn recorded_requests(&self) -> Vec<ToEnclaveTransformationRequest> {
        self.requests.borrow().clone()
    }
}

impl MpcToEnclaveSource for RecordingMpcServer {
    fn request_to_enclave_transformation(
        &self,
        request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        self.requests.borrow_mut().push(request.clone());
        self.inner.request_to_enclave_transformation(request)
    }
}

// ---------- chain source ----------

struct FixedChainSource {
    events: Vec<ChainEvent>,
}

impl FixedChainSource {
    fn new(events: Vec<ChainEvent>) -> Self {
        Self { events }
    }
}

impl ChainEventSource for FixedChainSource {
    fn poll(&mut self, _view: ChainView) -> ChainViewPoll {
        ChainViewPoll {
            events: std::mem::take(&mut self.events),
            orphaned_event_refs: Vec::new(),
        }
    }
}
