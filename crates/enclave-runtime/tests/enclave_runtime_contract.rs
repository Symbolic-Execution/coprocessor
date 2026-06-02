//! Contract tests for the runtime-neutral Enclave boundary used by the
//! Coprocessor Host. Each test drives the public trait through a fake runtime
//! to prove a Coprocessor Host can schedule Enclave Execution without
//! depending on any runtime-specific details (Nitro or otherwise).

use coprocessor_ciphertext_binding::{AttestationDigest, EnclaveCiphertextV1, RequestId};
use coprocessor_enclave_runtime::{
    EnclaveExecutionError, EnclaveRuntime, FakeEnclaveRuntime, ResolutionTask,
};
use coprocessor_handle_graph_core::{
    ChainId, ContractAddress, HandleId, HandleKey, HandleType, OperationCode,
};

fn handle_key(id: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(1),
        contract_address: ContractAddress([0xAB; 20]),
        handle_id: HandleId([id; 32]),
    }
}

fn enclave_ciphertext(tag: u8) -> EnclaveCiphertextV1 {
    EnclaveCiphertextV1 {
        version: 1,
        aad: vec![tag, 0xAA],
        wrapped_key: vec![tag, 0xBB],
        ciphertext: vec![tag, 0xCC],
    }
}

fn add_task() -> ResolutionTask {
    ResolutionTask {
        request_id: RequestId([0x10; 32]),
        attestation_digest: AttestationDigest([0x5E; 32]),
        output_handle_key: handle_key(3),
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![handle_key(1), handle_key(2)],
        input_ciphertexts: vec![enclave_ciphertext(1), enclave_ciphertext(2)],
    }
}

#[test]
fn enclave_execution_returns_system_ciphertext_and_receipt() {
    let runtime = FakeEnclaveRuntime::deterministic();
    let task = add_task();

    let outcome = runtime
        .execute(&task)
        .expect("deterministic fake must succeed for a well-formed task");

    // Encrypted output: host code may forward this to handle-graph-core, but
    // it must never see plaintext bytes from the runtime.
    assert!(!outcome.system_ciphertext.ciphertext.is_empty());
    assert!(!outcome.system_ciphertext.wrapped_key.is_empty());
    assert!(!outcome.system_ciphertext.aad.is_empty());

    let receipt = &outcome.receipt;
    assert_eq!(receipt.operation_code, OperationCode::Add);
    assert_eq!(receipt.output_handle_key, task.output_handle_key);
    assert_eq!(receipt.input_handle_keys, task.input_handle_keys);
    assert_eq!(receipt.attestation_digest, task.attestation_digest);
}

#[test]
fn deterministic_runtime_returns_distinct_ciphertexts_for_distinct_tasks() {
    let runtime = FakeEnclaveRuntime::deterministic();
    let mut other = add_task();
    other.output_handle_key = handle_key(9);

    let a = runtime.execute(&add_task()).unwrap().system_ciphertext;
    let b = runtime.execute(&other).unwrap().system_ciphertext;

    assert_ne!(a.ciphertext, b.ciphertext);
}

#[test]
fn input_count_mismatch_surfaces_domain_shaped_error() {
    let runtime = FakeEnclaveRuntime::deterministic();
    let mut task = add_task();
    task.input_ciphertexts.pop();

    let err = runtime
        .execute(&task)
        .expect_err("missing input ciphertext must be rejected");

    assert_eq!(
        err,
        EnclaveExecutionError::InputCountMismatch {
            handle_key_count: 2,
            ciphertext_count: 1,
        }
    );
}

#[test]
fn attestation_mismatch_surfaces_domain_shaped_error() {
    let expected = AttestationDigest([0x42; 32]);
    let runtime = FakeEnclaveRuntime::with_expected_attestation(expected);
    let task = add_task();

    let err = runtime
        .execute(&task)
        .expect_err("non-matching attestation must be rejected");

    assert_eq!(
        err,
        EnclaveExecutionError::AttestationVerificationFailure {
            expected,
            actual: task.attestation_digest,
        }
    );
}

#[test]
fn host_code_drives_runtime_through_public_trait() {
    // A miniature host scheduler: pulls tasks out of a queue and asks any
    // EnclaveRuntime to execute them. This proves host code is decoupled from
    // the runtime implementation.
    fn run_all<R: EnclaveRuntime>(
        runtime: &R,
        tasks: &[ResolutionTask],
    ) -> Vec<(HandleKey, OperationCode)> {
        tasks
            .iter()
            .map(|task| {
                let outcome = runtime.execute(task).expect("runtime must succeed");
                (
                    outcome.receipt.output_handle_key,
                    outcome.receipt.operation_code,
                )
            })
            .collect()
    }

    let runtime = FakeEnclaveRuntime::deterministic();
    let mut second = add_task();
    second.output_handle_key = handle_key(4);
    second.operation_code = OperationCode::Sub;

    let summaries = run_all(&runtime, &[add_task(), second]);

    assert_eq!(
        summaries,
        vec![
            (handle_key(3), OperationCode::Add),
            (handle_key(4), OperationCode::Sub),
        ]
    );
}

#[test]
fn host_code_can_swap_runtime_via_trait_object() {
    // Same scheduler, but through a `&dyn EnclaveRuntime`. This proves the
    // trait is object-safe and host code can hold any approved runtime.
    let runtime = FakeEnclaveRuntime::deterministic();
    let runtime_ref: &dyn EnclaveRuntime = &runtime;
    let outcome = runtime_ref
        .execute(&add_task())
        .expect("dyn dispatch must work");
    assert_eq!(outcome.receipt.operation_code, OperationCode::Add);
}
