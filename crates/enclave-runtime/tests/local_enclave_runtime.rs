//! Integration tests for [`LocalEnclaveRuntime`], the in-process Enclave used
//! for deterministic testing of the Coprocessor / Enclave boundary. Drives the
//! same public `EnclaveRuntime` trait the host uses, so these tests exercise
//! the contract end-to-end: a host scheduler hands the runtime a Resolution
//! Task, the runtime verifies the per-input `EnclaveAadV1`, evaluates the
//! initial private operation surface, and returns a `SystemCiphertextV1` plus
//! a Materialization Receipt.
//!
//! Host-facing assertions in this file deliberately never inspect plaintext
//! Private Values. The runtime exposes test-only sealing helpers that let test
//! fixtures construct sealed inputs and verify sealed outputs without crossing
//! the trait surface with cleartext.

use coprocessor_ciphertext_binding::{
    AttestationDigest, DomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId as AadHandleId, KeyId,
    RequestId,
};
use coprocessor_enclave_runtime::{
    EnclaveExecutionError, EnclaveRuntime, InputAadField, LocalEnclaveConfig, LocalEnclaveRuntime,
    ResolutionTask,
};
use coprocessor_handle_graph_core::{
    ChainId, ContractAddress, HandleId, HandleKey, HandleType, OperationCode,
};

const TEST_CHAIN_ID: u64 = 0x1A2B;
const TEST_DOMAIN_ID: DomainId = DomainId([0xD0; 32]);
const TEST_ATTESTATION: AttestationDigest = AttestationDigest([0x5E; 32]);
const TEST_ENCLAVE_KEY_ID: KeyId = KeyId([0xE1; 32]);
const TEST_SYSTEM_KEY_ID: KeyId = KeyId([0x57; 32]);
const TEST_SEALING_SECRET: [u8; 32] = [0xAA; 32];

fn runtime() -> LocalEnclaveRuntime {
    LocalEnclaveRuntime::new(LocalEnclaveConfig {
        chain_id: TEST_CHAIN_ID,
        domain_id: TEST_DOMAIN_ID,
        attestation_digest: TEST_ATTESTATION,
        enclave_key_id: TEST_ENCLAVE_KEY_ID,
        system_key_id: TEST_SYSTEM_KEY_ID,
        sealing_secret: TEST_SEALING_SECRET,
    })
}

fn handle_key(id: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(TEST_CHAIN_ID),
        contract_address: ContractAddress([0xAB; 20]),
        handle_id: HandleId([id; 32]),
    }
}

fn request_id() -> RequestId {
    RequestId([0x10; 32])
}

fn u256_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

fn add_task(runtime: &LocalEnclaveRuntime, lhs: u64, rhs: u64) -> (ResolutionTask, [u8; 32]) {
    let req = request_id();
    let lhs_key = handle_key(1);
    let rhs_key = handle_key(2);
    let out_key = handle_key(3);

    let lhs_ct = runtime.seal_suint256_input(req, lhs_key, u256_from_u64(lhs));
    let rhs_ct = runtime.seal_suint256_input(req, rhs_key, u256_from_u64(rhs));

    let task = ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: out_key,
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![lhs_key, rhs_key],
        input_ciphertexts: vec![lhs_ct, rhs_ct],
    };

    (task, u256_from_u64(lhs.wrapping_add(rhs)))
}

#[test]
fn evaluates_suint256_add_end_to_end_through_enclave_boundary() {
    let runtime = runtime();
    let (task, expected_sum) = add_task(&runtime, 3, 4);

    let outcome = runtime
        .execute(&task)
        .expect("well-formed suint256 Add must succeed");

    // Host-facing assertions: only structural / receipt fields, never plaintext.
    assert_eq!(outcome.receipt.operation_code, OperationCode::Add);
    assert_eq!(outcome.receipt.output_handle_key, task.output_handle_key);
    assert_eq!(outcome.receipt.input_handle_keys, task.input_handle_keys);
    assert_eq!(outcome.receipt.attestation_digest, TEST_ATTESTATION);
    assert!(!outcome.system_ciphertext.aad.is_empty());
    assert!(!outcome.system_ciphertext.wrapped_key.is_empty());
    assert!(!outcome.system_ciphertext.ciphertext.is_empty());

    // The plaintext result must NEVER appear in the host-visible ciphertext
    // bytes. This guards the boundary: only the runtime's test-only unseal can
    // recover the value, never the host.
    assert!(
        !contains_subslice(&outcome.system_ciphertext.ciphertext, &expected_sum),
        "plaintext sum bytes leaked into the system ciphertext",
    );

    // Test-only unseal (NOT a host-facing path) recovers the sum.
    let recovered = runtime
        .unseal_suint256_output(&outcome.system_ciphertext)
        .expect("test-only unseal must succeed for our own output");
    assert_eq!(recovered, expected_sum);
}

#[test]
fn host_only_receives_system_ciphertext_and_receipt_no_plaintext() {
    // Drive the runtime through a `&dyn EnclaveRuntime` trait object to model a
    // host scheduler that has no knowledge of which runtime it holds. Assert
    // that the only outputs are the encrypted envelope and the receipt; no
    // type from the boundary exposes plaintext.
    let runtime = runtime();
    let (task, _expected_sum) = add_task(&runtime, 11, 31);
    let trait_object: &dyn EnclaveRuntime = &runtime;

    let outcome = trait_object
        .execute(&task)
        .expect("trait-object dispatch must succeed");

    assert_eq!(outcome.receipt.operation_code, OperationCode::Add);
    // The system ciphertext bytes are opaque to the host: we only assert they
    // are non-empty and structurally distinct from any input ciphertext.
    for input in &task.input_ciphertexts {
        assert_ne!(outcome.system_ciphertext.ciphertext, input.ciphertext);
    }
}

#[test]
fn input_aad_decode_failure_surfaces_domain_shaped_error() {
    let runtime = runtime();
    let (mut task, _) = add_task(&runtime, 1, 2);
    // Corrupt the second input's AAD bytes so CBOR decode fails before any
    // field-level checks. The runtime must report the failing index.
    task.input_ciphertexts[1].aad = vec![0x00; 4];

    let err = runtime
        .execute(&task)
        .expect_err("malformed AAD must reject");

    assert_eq!(
        err,
        EnclaveExecutionError::InputAadVerificationFailed {
            input_index: 1,
            field: InputAadField::Decode,
        }
    );
}

#[test]
fn input_aad_with_wrong_handle_id_is_rejected() {
    let runtime = runtime();
    let req = request_id();
    let lhs_key = handle_key(1);
    let rhs_key = handle_key(2);

    // Seal the second input bound to a DIFFERENT handle id than the task
    // claims. The runtime must reject because the AAD binding does not match
    // the ordered input handle key for this position.
    let wrong_key = HandleKey {
        handle_id: HandleId([0xCC; 32]),
        ..rhs_key
    };
    let lhs_ct = runtime.seal_suint256_input(req, lhs_key, u256_from_u64(1));
    let rhs_ct = runtime.seal_suint256_input(req, wrong_key, u256_from_u64(2));

    let task = ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: handle_key(3),
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![lhs_key, rhs_key],
        input_ciphertexts: vec![lhs_ct, rhs_ct],
    };

    let err = runtime
        .execute(&task)
        .expect_err("mismatched input handle id must reject");

    assert_eq!(
        err,
        EnclaveExecutionError::InputAadVerificationFailed {
            input_index: 1,
            field: InputAadField::HandleId,
        }
    );
}

#[test]
fn input_aad_with_wrong_request_id_is_rejected() {
    let runtime = runtime();
    let req = request_id();
    let other_req = RequestId([0x99; 32]);
    let lhs_key = handle_key(1);
    let rhs_key = handle_key(2);

    let lhs_ct = runtime.seal_suint256_input(other_req, lhs_key, u256_from_u64(1));
    let rhs_ct = runtime.seal_suint256_input(req, rhs_key, u256_from_u64(2));

    let task = ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: handle_key(3),
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![lhs_key, rhs_key],
        input_ciphertexts: vec![lhs_ct, rhs_ct],
    };

    let err = runtime
        .execute(&task)
        .expect_err("mismatched request id must reject");

    assert_eq!(
        err,
        EnclaveExecutionError::InputAadVerificationFailed {
            input_index: 0,
            field: InputAadField::RequestId,
        }
    );
}

#[test]
fn input_aad_with_wrong_type_tag_is_rejected() {
    let runtime = runtime();
    let req = request_id();
    let lhs_key = handle_key(1);
    let rhs_key = handle_key(2);

    // Hand-craft an EnclaveAadV1 with the wrong type_tag for the operation.
    let bad_aad = EnclaveAadV1 {
        version: 1,
        chain_id: TEST_CHAIN_ID,
        domain_id: TEST_DOMAIN_ID,
        request_id: req,
        handle_id: AadHandleId(lhs_key.handle_id.0),
        type_tag: "sbool".to_string(),
        attestation_digest: TEST_ATTESTATION,
        key_id: TEST_ENCLAVE_KEY_ID,
    };
    let bad_ct = EnclaveCiphertextV1 {
        version: 1,
        aad: bad_aad.encode(),
        wrapped_key: vec![0xAB; 8],
        ciphertext: vec![0xCD; 32],
    };

    let rhs_ct = runtime.seal_suint256_input(req, rhs_key, u256_from_u64(2));

    let task = ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: handle_key(3),
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![lhs_key, rhs_key],
        input_ciphertexts: vec![bad_ct, rhs_ct],
    };

    let err = runtime
        .execute(&task)
        .expect_err("wrong type tag must reject");

    assert_eq!(
        err,
        EnclaveExecutionError::InputAadVerificationFailed {
            input_index: 0,
            field: InputAadField::TypeTag,
        }
    );
}

#[test]
fn task_attestation_mismatch_surfaces_attestation_error() {
    let runtime = runtime();
    let (mut task, _) = add_task(&runtime, 1, 2);
    task.attestation_digest = AttestationDigest([0x00; 32]);

    let err = runtime
        .execute(&task)
        .expect_err("wrong task attestation must reject");

    assert_eq!(
        err,
        EnclaveExecutionError::AttestationVerificationFailure {
            expected: TEST_ATTESTATION,
            actual: AttestationDigest([0x00; 32]),
        }
    );
}

#[test]
fn unsupported_operation_output_type_pair_surfaces_operation_not_supported() {
    // The local Enclave evaluates every OperationCode in the spec's initial
    // surface, but only against the operation's well-typed output. `Add` over
    // an `Sbool` output Handle is a malformed task and must surface as
    // OperationNotSupported without touching plaintext.
    let runtime = runtime();
    let (mut task, _) = add_task(&runtime, 1, 2);
    task.output_handle_type = HandleType::Sbool;

    let err = runtime
        .execute(&task)
        .expect_err("Add with Sbool output is not a valid (op, type) pair");

    assert_eq!(
        err,
        EnclaveExecutionError::OperationNotSupported(OperationCode::Add)
    );
}

// ----------------------------------------------------------------------------
// Full OperationCode surface: arithmetic, comparison, boolean, and Select.
// Each test drives the runtime through the public `EnclaveRuntime` trait,
// builds inputs via test-only sealing helpers, and recovers results via the
// test-only unseal helpers. Plaintext never crosses the trait surface.
// ----------------------------------------------------------------------------

fn suint256_binop_task(
    runtime: &LocalEnclaveRuntime,
    op: OperationCode,
    output_type: HandleType,
    lhs: [u8; 32],
    rhs: [u8; 32],
) -> ResolutionTask {
    let req = request_id();
    let lhs_key = handle_key(1);
    let rhs_key = handle_key(2);
    let out_key = handle_key(3);

    let lhs_ct = runtime.seal_suint256_input(req, lhs_key, lhs);
    let rhs_ct = runtime.seal_suint256_input(req, rhs_key, rhs);

    ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: out_key,
        operation_code: op,
        output_handle_type: output_type,
        input_handle_keys: vec![lhs_key, rhs_key],
        input_ciphertexts: vec![lhs_ct, rhs_ct],
    }
}

fn sbool_binop_task(
    runtime: &LocalEnclaveRuntime,
    op: OperationCode,
    lhs: bool,
    rhs: bool,
) -> ResolutionTask {
    let req = request_id();
    let lhs_key = handle_key(1);
    let rhs_key = handle_key(2);
    let out_key = handle_key(3);

    let lhs_ct = runtime.seal_sbool_input(req, lhs_key, lhs);
    let rhs_ct = runtime.seal_sbool_input(req, rhs_key, rhs);

    ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: out_key,
        operation_code: op,
        output_handle_type: HandleType::Sbool,
        input_handle_keys: vec![lhs_key, rhs_key],
        input_ciphertexts: vec![lhs_ct, rhs_ct],
    }
}

fn run_and_unseal_suint256(runtime: &LocalEnclaveRuntime, task: &ResolutionTask) -> [u8; 32] {
    let outcome = runtime
        .execute(task)
        .expect("well-formed task must succeed");
    runtime
        .unseal_suint256_output(&outcome.system_ciphertext)
        .expect("output must unseal as suint256")
}

fn run_and_unseal_sbool(runtime: &LocalEnclaveRuntime, task: &ResolutionTask) -> bool {
    let outcome = runtime
        .execute(task)
        .expect("well-formed task must succeed");
    runtime
        .unseal_sbool_output(&outcome.system_ciphertext)
        .expect("output must unseal as sbool")
}

#[test]
fn evaluates_suint256_sub_with_wrapping_semantics() {
    // 2^256-modular subtraction: spec says `suint256` arithmetic is wrapping.
    // The test covers a non-wrapping case AND the wrap-around (0 - 1 = 2^256-1).
    let runtime = runtime();

    let task = suint256_binop_task(
        &runtime,
        OperationCode::Sub,
        HandleType::Suint256,
        u256_from_u64(10),
        u256_from_u64(3),
    );
    assert_eq!(run_and_unseal_suint256(&runtime, &task), u256_from_u64(7));

    let zero = u256_from_u64(0);
    let one = u256_from_u64(1);
    let wrap_task = suint256_binop_task(
        &runtime,
        OperationCode::Sub,
        HandleType::Suint256,
        zero,
        one,
    );
    assert_eq!(run_and_unseal_suint256(&runtime, &wrap_task), [0xFF; 32]);
}

#[test]
fn evaluates_suint256_eq_to_sbool() {
    let runtime = runtime();
    let eq_task = suint256_binop_task(
        &runtime,
        OperationCode::Eq,
        HandleType::Sbool,
        u256_from_u64(42),
        u256_from_u64(42),
    );
    assert!(run_and_unseal_sbool(&runtime, &eq_task));

    let ne_task = suint256_binop_task(
        &runtime,
        OperationCode::Eq,
        HandleType::Sbool,
        u256_from_u64(42),
        u256_from_u64(43),
    );
    assert!(!run_and_unseal_sbool(&runtime, &ne_task));
}

#[test]
fn evaluates_suint256_lt_to_sbool() {
    let runtime = runtime();
    for (lhs, rhs, expected) in [(3u64, 4u64, true), (4, 4, false), (5, 4, false)] {
        let task = suint256_binop_task(
            &runtime,
            OperationCode::Lt,
            HandleType::Sbool,
            u256_from_u64(lhs),
            u256_from_u64(rhs),
        );
        assert_eq!(run_and_unseal_sbool(&runtime, &task), expected);
    }
}

#[test]
fn evaluates_suint256_lte_to_sbool() {
    let runtime = runtime();
    for (lhs, rhs, expected) in [(3u64, 4u64, true), (4, 4, true), (5, 4, false)] {
        let task = suint256_binop_task(
            &runtime,
            OperationCode::Lte,
            HandleType::Sbool,
            u256_from_u64(lhs),
            u256_from_u64(rhs),
        );
        assert_eq!(run_and_unseal_sbool(&runtime, &task), expected);
    }
}

#[test]
fn evaluates_suint256_gt_to_sbool() {
    let runtime = runtime();
    for (lhs, rhs, expected) in [(3u64, 4u64, false), (4, 4, false), (5, 4, true)] {
        let task = suint256_binop_task(
            &runtime,
            OperationCode::Gt,
            HandleType::Sbool,
            u256_from_u64(lhs),
            u256_from_u64(rhs),
        );
        assert_eq!(run_and_unseal_sbool(&runtime, &task), expected);
    }
}

#[test]
fn evaluates_suint256_gte_to_sbool() {
    let runtime = runtime();
    for (lhs, rhs, expected) in [(3u64, 4u64, false), (4, 4, true), (5, 4, true)] {
        let task = suint256_binop_task(
            &runtime,
            OperationCode::Gte,
            HandleType::Sbool,
            u256_from_u64(lhs),
            u256_from_u64(rhs),
        );
        assert_eq!(run_and_unseal_sbool(&runtime, &task), expected);
    }
}

#[test]
fn evaluates_sbool_and_or_truth_tables() {
    let runtime = runtime();
    for (a, b) in [(false, false), (false, true), (true, false), (true, true)] {
        let and_task = sbool_binop_task(&runtime, OperationCode::And, a, b);
        assert_eq!(run_and_unseal_sbool(&runtime, &and_task), a && b);

        let or_task = sbool_binop_task(&runtime, OperationCode::Or, a, b);
        assert_eq!(run_and_unseal_sbool(&runtime, &or_task), a || b);
    }
}

#[test]
fn evaluates_sbool_not_unary() {
    let runtime = runtime();
    let req = request_id();
    let in_key = handle_key(1);
    let out_key = handle_key(2);

    for value in [false, true] {
        let ct = runtime.seal_sbool_input(req, in_key, value);
        let task = ResolutionTask {
            request_id: req,
            attestation_digest: TEST_ATTESTATION,
            output_handle_key: out_key,
            operation_code: OperationCode::Not,
            output_handle_type: HandleType::Sbool,
            input_handle_keys: vec![in_key],
            input_ciphertexts: vec![ct],
        };
        assert_eq!(run_and_unseal_sbool(&runtime, &task), !value);
    }
}

#[test]
fn evaluates_select_for_suint256_branches_preserving_order() {
    // Select takes (predicate sbool, when_true, when_false) in that order. The
    // local Enclave evaluates both branches inside the boundary and only
    // releases the chosen ciphertext through a SystemCiphertextV1; host code
    // cannot tell which branch was selected from the encrypted envelope.
    let runtime = runtime();
    let req = request_id();
    let pred_key = handle_key(1);
    let true_key = handle_key(2);
    let false_key = handle_key(3);
    let out_key = handle_key(4);

    let when_true = u256_from_u64(0xAAAA);
    let when_false = u256_from_u64(0x5555);

    let build_task = |predicate: bool| {
        let pred_ct = runtime.seal_sbool_input(req, pred_key, predicate);
        let true_ct = runtime.seal_suint256_input(req, true_key, when_true);
        let false_ct = runtime.seal_suint256_input(req, false_key, when_false);
        ResolutionTask {
            request_id: req,
            attestation_digest: TEST_ATTESTATION,
            output_handle_key: out_key,
            operation_code: OperationCode::Select,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![pred_key, true_key, false_key],
            input_ciphertexts: vec![pred_ct, true_ct, false_ct],
        }
    };

    let true_task = build_task(true);
    let true_outcome = runtime
        .execute(&true_task)
        .expect("Select with true predicate must succeed");
    assert_eq!(
        runtime
            .unseal_suint256_output(&true_outcome.system_ciphertext)
            .expect("output must unseal"),
        when_true,
    );
    // The host-visible ciphertext bytes do not contain either branch's plaintext.
    assert!(!contains_subslice(
        &true_outcome.system_ciphertext.ciphertext,
        &when_true,
    ));
    assert!(!contains_subslice(
        &true_outcome.system_ciphertext.ciphertext,
        &when_false,
    ));

    let false_task = build_task(false);
    let false_outcome = runtime
        .execute(&false_task)
        .expect("Select with false predicate must succeed");
    assert_eq!(
        runtime
            .unseal_suint256_output(&false_outcome.system_ciphertext)
            .expect("output must unseal"),
        when_false,
    );
}

#[test]
fn evaluates_select_for_sbool_branches() {
    let runtime = runtime();
    let req = request_id();
    let pred_key = handle_key(1);
    let true_key = handle_key(2);
    let false_key = handle_key(3);
    let out_key = handle_key(4);

    for (predicate, expected) in [(true, true), (false, false)] {
        let pred_ct = runtime.seal_sbool_input(req, pred_key, predicate);
        let true_ct = runtime.seal_sbool_input(req, true_key, true);
        let false_ct = runtime.seal_sbool_input(req, false_key, false);
        let task = ResolutionTask {
            request_id: req,
            attestation_digest: TEST_ATTESTATION,
            output_handle_key: out_key,
            operation_code: OperationCode::Select,
            output_handle_type: HandleType::Sbool,
            input_handle_keys: vec![pred_key, true_key, false_key],
            input_ciphertexts: vec![pred_ct, true_ct, false_ct],
        };
        assert_eq!(run_and_unseal_sbool(&runtime, &task), expected);
    }
}

#[test]
fn sbool_operation_rejects_suint256_typed_input() {
    // The position-aware type check: `And` expects both inputs to bind the
    // `sbool` type tag. An suint256-sealed input at index 1 must surface as a
    // TypeTag mismatch at that position.
    let runtime = runtime();
    let req = request_id();
    let lhs_key = handle_key(1);
    let rhs_key = handle_key(2);
    let out_key = handle_key(3);

    let lhs_ct = runtime.seal_sbool_input(req, lhs_key, true);
    let rhs_ct = runtime.seal_suint256_input(req, rhs_key, u256_from_u64(1));

    let task = ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: out_key,
        operation_code: OperationCode::And,
        output_handle_type: HandleType::Sbool,
        input_handle_keys: vec![lhs_key, rhs_key],
        input_ciphertexts: vec![lhs_ct, rhs_ct],
    };

    let err = runtime
        .execute(&task)
        .expect_err("wrong typed input at index 1 must reject");
    assert_eq!(
        err,
        EnclaveExecutionError::InputAadVerificationFailed {
            input_index: 1,
            field: InputAadField::TypeTag,
        }
    );
}

#[test]
fn select_rejects_sbool_predicate_typed_as_suint256() {
    // Position-aware type check for Select: index 0 must be the sbool
    // predicate. An suint256-sealed input there must surface as a TypeTag
    // mismatch at position 0.
    let runtime = runtime();
    let req = request_id();
    let pred_key = handle_key(1);
    let true_key = handle_key(2);
    let false_key = handle_key(3);
    let out_key = handle_key(4);

    let pred_ct = runtime.seal_suint256_input(req, pred_key, u256_from_u64(1));
    let true_ct = runtime.seal_suint256_input(req, true_key, u256_from_u64(0xAA));
    let false_ct = runtime.seal_suint256_input(req, false_key, u256_from_u64(0x55));

    let task = ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: out_key,
        operation_code: OperationCode::Select,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![pred_key, true_key, false_key],
        input_ciphertexts: vec![pred_ct, true_ct, false_ct],
    };

    let err = runtime
        .execute(&task)
        .expect_err("non-sbool predicate must reject");
    assert_eq!(
        err,
        EnclaveExecutionError::InputAadVerificationFailed {
            input_index: 0,
            field: InputAadField::TypeTag,
        }
    );
}

#[test]
fn not_with_two_inputs_surfaces_input_count_mismatch() {
    let runtime = runtime();
    let req = request_id();
    let a_key = handle_key(1);
    let b_key = handle_key(2);
    let out_key = handle_key(3);

    let a_ct = runtime.seal_sbool_input(req, a_key, true);
    let b_ct = runtime.seal_sbool_input(req, b_key, false);

    let task = ResolutionTask {
        request_id: req,
        attestation_digest: TEST_ATTESTATION,
        output_handle_key: out_key,
        operation_code: OperationCode::Not,
        output_handle_type: HandleType::Sbool,
        input_handle_keys: vec![a_key, b_key],
        input_ciphertexts: vec![a_ct, b_ct],
    };

    let err = runtime
        .execute(&task)
        .expect_err("Not is unary; two inputs must reject");
    assert_eq!(
        err,
        EnclaveExecutionError::InputCountMismatch {
            handle_key_count: 2,
            ciphertext_count: 2,
        }
    );
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
