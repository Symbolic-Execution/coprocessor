//! End-to-end scenario tests for the Handle Graph Core.
//!
//! Each scenario strings together Imported Handles, Plaintext Handles, Derived
//! Handles, Resolution Readiness, Orphan Discard, and canonical/audit queries
//! to prove the Handle Graph Core behaves as one deep module through its
//! public interface.
//!
//! These tests intentionally do not exercise private helpers, internal storage,
//! or implementation details. They consume the same spec-shaped ChainEvent,
//! opaque SystemCiphertextV1, and opaque MaterializationReceipt fixtures that
//! the Internal Coordinator API and future Resolution Scheduler will see.
//!
//! The import list at the top is itself part of the contract: the Handle Graph
//! Core acceptance surface requires no RPC client, ABI decoder, persistence
//! crate, MPC client, Enclave runtime, HTTP server, or real cryptographic
//! codec — only the public domain types exported from
//! `coprocessor_handle_graph_core`. If a future change adds such an external
//! dependency to drive the core, this file will stop compiling on its own.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    FailureReason, HandleGraphCore, HandleId, HandleKey, HandleLineage, HandleRecord, HandleState,
    HandleType, ImportedHandle, IngestionOutcome, LineageViolation, MaterializationReceipt,
    OperationCode, OperationViolation, PlaintextHandle, PublicPlaintextValue, ResolutionReadiness,
    SystemCiphertextV1,
};

const DEFAULT_DOMAIN: u8 = 9;

// ---------------------------------------------------------------------------
// Scenario A — Mixed-source graph reaches Resolution Readiness
//
// Acceptance criteria exercised:
//   * Combines Imported Handles, Plaintext Handles, and Derived Handles in one
//     Handle Graph.
//   * Covers a valid arithmetic operation (Add) reaching Resolution Readiness.
//   * Covers a valid comparison operation (Eq) reaching Resolution Readiness.
//   * Asserts Derived Handles remain Pending (do not become Ready) in this PRD.
// ---------------------------------------------------------------------------

#[test]
fn mixed_source_graph_reaches_resolution_readiness_with_arithmetic_and_comparison() {
    let mut core = HandleGraphCore::new();

    let imported = handle_key(1, 7, 1);
    let imported_ciphertext = SystemCiphertextV1(vec![0xA1, 0xA2]);
    let imported_receipt = MaterializationReceipt(vec![0xA3]);
    let _ = expect_recorded(core.apply_chain_event(imported_event(
        imported,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
        imported_ciphertext.clone(),
        imported_receipt,
    )));

    let plaintext = handle_key(1, 7, 2);
    let _ = expect_recorded(core.apply_chain_event(plaintext_event(
        plaintext,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
        PublicPlaintextValue(vec![0x10, 0x20]),
    )));
    let plaintext_ciphertext = ready_system_ciphertext(&core, &plaintext)
        .expect("plaintext source handle must materialize as Ready");

    let sum = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        sum,
        OperationCode::Add,
        HandleType::Suint256,
        vec![imported, plaintext],
        chain_event_ref(1, 2, 1),
    )));
    let equality = handle_key(1, 7, 11);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        equality,
        OperationCode::Eq,
        HandleType::Sbool,
        vec![imported, plaintext],
        chain_event_ref(1, 2, 2),
    )));

    assert_eq!(
        canonical_state(&core, &sum),
        Some(HandleState::Pending),
        "valid Add derived handle must be Pending in this PRD"
    );
    assert_eq!(
        canonical_state(&core, &equality),
        Some(HandleState::Pending),
        "valid Eq derived handle must be Pending in this PRD"
    );

    let ready = core.resolution_readiness();
    let sum_entry = find_readiness(&ready, &sum).expect("Add derived must be ready");
    assert_eq!(sum_entry.operation_code, OperationCode::Add);
    assert_eq!(sum_entry.output_handle_type, HandleType::Suint256);
    assert_eq!(sum_entry.input_handle_keys, vec![imported, plaintext]);
    assert_eq!(
        sum_entry.input_system_ciphertexts,
        vec![imported_ciphertext.clone(), plaintext_ciphertext.clone()],
        "readiness must surface ordered input ciphertexts mixing Imported + Plaintext sources"
    );

    let eq_entry = find_readiness(&ready, &equality).expect("Eq derived must be ready");
    assert_eq!(eq_entry.operation_code, OperationCode::Eq);
    assert_eq!(eq_entry.output_handle_type, HandleType::Sbool);
    assert_eq!(
        eq_entry.input_system_ciphertexts,
        vec![imported_ciphertext, plaintext_ciphertext],
    );

    assert_no_derived_is_ready(&core, &[sum, equality]);
}

// ---------------------------------------------------------------------------
// Scenario B — Select preserves predicate / when_true / when_false ordering
//
// Acceptance criterion exercised:
//   * Covers Select with ordered predicate, when_true, and when_false inputs.
// ---------------------------------------------------------------------------

#[test]
fn select_scenario_preserves_predicate_when_true_when_false_order_through_readiness() {
    let mut core = HandleGraphCore::new();

    let predicate = handle_key(1, 7, 30);
    let when_true = handle_key(1, 7, 31);
    let when_false = handle_key(1, 7, 32);
    let predicate_ciphertext = SystemCiphertextV1(vec![0xC0]);
    let when_true_ciphertext = SystemCiphertextV1(vec![0xC1]);
    let when_false_ciphertext = SystemCiphertextV1(vec![0xC2]);
    let _ = expect_recorded(core.apply_chain_event(imported_event(
        predicate,
        HandleType::Sbool,
        chain_event_ref(1, 1, 30),
        predicate_ciphertext.clone(),
        MaterializationReceipt(vec![0xEE]),
    )));
    let _ = expect_recorded(core.apply_chain_event(imported_event(
        when_true,
        HandleType::Suint256,
        chain_event_ref(1, 1, 31),
        when_true_ciphertext.clone(),
        MaterializationReceipt(vec![0xEE]),
    )));
    let _ = expect_recorded(core.apply_chain_event(imported_event(
        when_false,
        HandleType::Suint256,
        chain_event_ref(1, 1, 32),
        when_false_ciphertext.clone(),
        MaterializationReceipt(vec![0xEE]),
    )));

    let select_derived = handle_key(1, 7, 33);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        select_derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        chain_event_ref(1, 2, 1),
    )));

    let record = core
        .canonical_handle(&select_derived)
        .expect("select handle must be canonical");
    let HandleLineage::Derived {
        operation_code,
        ref input_handle_keys,
    } = record.lineage
    else {
        panic!("expected Derived lineage, got {:?}", record.lineage);
    };
    assert_eq!(operation_code, OperationCode::Select);
    assert_eq!(
        input_handle_keys,
        &vec![predicate, when_true, when_false],
        "Select lineage must preserve ordered inputs and must not be deduplicated"
    );
    assert_eq!(record.state, HandleState::Pending);

    let ready = core.resolution_readiness();
    let entry = find_readiness(&ready, &select_derived).expect("select handle must be ready");
    assert_eq!(
        entry.input_handle_keys,
        vec![predicate, when_true, when_false],
        "Select readiness must surface predicate, when-true, when-false in that order"
    );
    assert_eq!(
        entry.input_system_ciphertexts,
        vec![predicate_ciphertext, when_true_ciphertext, when_false_ciphertext],
        "Select readiness must align input ciphertexts with the ordered input handle keys"
    );

    assert_no_derived_is_ready(&core, &[select_derived]);
}

// ---------------------------------------------------------------------------
// Scenario C — Lineage and Operation violations are surfaced as Failed
//
// Acceptance criteria exercised:
//   * Covers LineageViolation for an unknown input Handle.
//   * Covers OperationViolation for wrong arity.
//   * Covers OperationViolation for wrong input HandleType.
//   * Failed derived handles do not reach Resolution Readiness.
// ---------------------------------------------------------------------------

#[test]
fn invalid_derived_operations_record_failed_records_and_never_reach_readiness() {
    let mut core = HandleGraphCore::new();
    let suint_a = handle_key(1, 7, 1);
    let suint_b = handle_key(1, 7, 2);
    let sbool_input = handle_key(1, 7, 3);
    seed_imported(&mut core, suint_a, HandleType::Suint256, chain_event_ref(1, 1, 1));
    seed_imported(&mut core, suint_b, HandleType::Suint256, chain_event_ref(1, 1, 2));
    seed_imported(&mut core, sbool_input, HandleType::Sbool, chain_event_ref(1, 1, 3));

    let unknown_input = handle_key(1, 7, 99);
    let lineage_violation = handle_key(1, 7, 40);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        lineage_violation,
        OperationCode::Add,
        HandleType::Suint256,
        vec![suint_a, unknown_input],
        chain_event_ref(1, 2, 1),
    )));
    assert_eq!(
        canonical_state(&core, &lineage_violation),
        Some(HandleState::Failed {
            reason: FailureReason::LineageViolation(LineageViolation::UnknownInputHandle {
                input_handle_key: unknown_input,
            }),
        }),
        "unknown input handle must Fail as LineageViolation::UnknownInputHandle"
    );

    let wrong_arity = handle_key(1, 7, 41);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        wrong_arity,
        OperationCode::Add,
        HandleType::Suint256,
        vec![suint_a],
        chain_event_ref(1, 2, 2),
    )));
    assert_eq!(
        canonical_state(&core, &wrong_arity),
        Some(HandleState::Failed {
            reason: FailureReason::OperationViolation(OperationViolation::WrongArity {
                operation_code: OperationCode::Add,
                expected: 2,
                actual: 1,
            }),
        }),
        "Add with one input must Fail as OperationViolation::WrongArity"
    );

    let wrong_input_type = handle_key(1, 7, 42);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        wrong_input_type,
        OperationCode::Add,
        HandleType::Suint256,
        vec![suint_a, sbool_input],
        chain_event_ref(1, 2, 3),
    )));
    assert_eq!(
        canonical_state(&core, &wrong_input_type),
        Some(HandleState::Failed {
            reason: FailureReason::OperationViolation(OperationViolation::WrongInputHandleType {
                input_index: 1,
                expected: HandleType::Suint256,
                actual: HandleType::Sbool,
            }),
        }),
        "Add with an Sbool input must Fail as OperationViolation::WrongInputHandleType"
    );

    let ready = core.resolution_readiness();
    for failed_key in [lineage_violation, wrong_arity, wrong_input_type] {
        assert!(
            find_readiness(&ready, &failed_key).is_none(),
            "Failed derived handle {:?} must never appear in Resolution Readiness",
            failed_key
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario D — Idempotent replay of previously consumed Chain Events
//
// Acceptance criterion exercised:
//   * Covers idempotent replay of previously consumed Chain Events for both
//     source ingestion and derived operations.
// ---------------------------------------------------------------------------

#[test]
fn replayed_chain_events_are_idempotent_across_source_and_derived_ingestion() {
    let mut core = HandleGraphCore::new();
    let imported = handle_key(1, 7, 1);
    let imported_event_ref = chain_event_ref(1, 1, 1);
    let imported_ciphertext = SystemCiphertextV1(vec![0xA1]);
    let imported_receipt = MaterializationReceipt(vec![0xA2]);
    let _ = expect_recorded(core.apply_chain_event(imported_event(
        imported,
        HandleType::Suint256,
        imported_event_ref,
        imported_ciphertext.clone(),
        imported_receipt.clone(),
    )));

    let imported_other = handle_key(1, 7, 2);
    seed_imported(
        &mut core,
        imported_other,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );

    let derived = handle_key(1, 7, 10);
    let derived_event_ref = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![imported, imported_other],
        derived_event_ref,
    )));

    let replay_imported = core.apply_chain_event(imported_event(
        imported,
        HandleType::Suint256,
        imported_event_ref,
        SystemCiphertextV1(vec![0xFF, 0xFF]),
        MaterializationReceipt(vec![0xFF]),
    ));
    assert!(
        matches!(replay_imported, IngestionOutcome::Idempotent),
        "replaying an Imported Handle by ChainEventRef must be Idempotent, got {:?}",
        replay_imported
    );

    let replay_derived = core.apply_chain_event(derived_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![imported, imported_other],
        derived_event_ref,
    ));
    assert!(
        matches!(replay_derived, IngestionOutcome::Idempotent),
        "replaying a Derived Handle Operation by ChainEventRef must be Idempotent, got {:?}",
        replay_derived
    );

    let record = core
        .canonical_handle(&imported)
        .expect("imported must still be canonical after replay");
    assert_eq!(
        record.state,
        HandleState::Ready {
            system_ciphertext: imported_ciphertext,
            materialization_receipt: imported_receipt,
        },
        "replay must not overwrite the original Ready payload"
    );

    let derived_record = core
        .canonical_handle(&derived)
        .expect("derived must still be canonical after replay");
    assert_eq!(derived_record.state, HandleState::Pending);
}

// ---------------------------------------------------------------------------
// Scenario E — Unknown Handle Keys are reported as unknown
//
// Acceptance criterion exercised:
//   * Covers unknown Handle Key query behavior: canonical query returns None
//     (not Pending, not a placeholder), and the audit query does not invent
//     records either.
// ---------------------------------------------------------------------------

#[test]
fn unknown_handle_key_is_reported_unknown_on_both_canonical_and_audit_paths() {
    let mut core = HandleGraphCore::new();
    let seeded = handle_key(1, 7, 1);
    seed_imported(&mut core, seeded, HandleType::Suint256, chain_event_ref(1, 1, 1));

    let unknown = handle_key(1, 7, 99);
    let unknown_other_chain = handle_key(2, 7, 1);
    let unknown_other_contract = handle_key(1, 8, 1);

    for unseen in [unknown, unknown_other_chain, unknown_other_contract] {
        assert!(
            core.canonical_handle(&unseen).is_none(),
            "unknown Handle Key {:?} must be None on canonical query (not Pending placeholder)",
            unseen
        );
        assert!(
            core.handle_record_for_audit(&unseen).is_none(),
            "unknown Handle Key {:?} must be None on audit query — the audit path must not invent records",
            unseen
        );
    }

    assert!(
        core.canonical_handle(&seeded).is_some(),
        "seeded handle remains visible — unknown queries do not destabilize known records"
    );
}

// ---------------------------------------------------------------------------
// Scenario F — Orphan Discard cascades, canonical hides, audit reveals
//
// Acceptance criteria exercised:
//   * Covers Orphan Discard of a Source Handle and cascade to downstream
//     Derived Handles, including multi-hop descendants.
//   * Covers canonical queries hiding tombstoned records.
//   * Covers audit/debug queries inspecting tombstoned records (event_ref,
//     handle_type, original state, tombstone flag).
//   * Cascade-tombstoned handles drop out of Resolution Readiness.
// ---------------------------------------------------------------------------

#[test]
fn orphan_discard_cascades_through_derived_handles_with_canonical_and_audit_paths_diverging() {
    // Graph: a -> c -> d
    //        b -> c
    //        other -> d
    //
    // Tombstoning a must cascade to c and to d. b and other remain canonical.
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let other = handle_key(1, 7, 3);
    let a_event = chain_event_ref(1, 1, 1);
    let b_event = chain_event_ref(1, 1, 2);
    let other_event = chain_event_ref(1, 1, 3);
    seed_imported(&mut core, a, HandleType::Suint256, a_event);
    seed_imported(&mut core, b, HandleType::Suint256, b_event);
    seed_imported(&mut core, other, HandleType::Suint256, other_event);

    let c = handle_key(1, 7, 10);
    let c_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        c,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        c_event,
    )));
    let d = handle_key(1, 7, 11);
    let d_event = chain_event_ref(1, 2, 2);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        d,
        OperationCode::Add,
        HandleType::Suint256,
        vec![c, other],
        d_event,
    )));

    // Pre-tombstone: c is Resolution-Ready, d depends on Pending c so it is not.
    let pre = core.resolution_readiness();
    assert!(
        find_readiness(&pre, &c).is_some(),
        "before discard, c must be Resolution-Ready"
    );
    assert!(
        find_readiness(&pre, &d).is_none(),
        "before discard, d must not be Ready — its input c is Pending"
    );

    let outcome = core.apply_orphan_discard(&[a_event]);
    assert_eq!(outcome.directly_tombstoned, vec![a]);
    let cascaded: std::collections::HashSet<HandleKey> =
        outcome.cascade_tombstoned.iter().copied().collect();
    assert_eq!(
        cascaded,
        [c, d].into_iter().collect(),
        "cascade must reach every transitive descendant"
    );

    for tombstoned in [a, c, d] {
        assert!(
            core.canonical_handle(&tombstoned).is_none(),
            "canonical query must hide tombstoned Handle Key {:?}",
            tombstoned
        );
        let audit = core
            .handle_record_for_audit(&tombstoned)
            .expect("audit query must still surface tombstoned record");
        assert!(audit.is_tombstoned, "audit must reveal tombstone status");
    }

    let a_audit = core
        .handle_record_for_audit(&a)
        .expect("audit must surface tombstoned source");
    assert_eq!(a_audit.event_ref, a_event);
    assert_eq!(a_audit.handle_type, HandleType::Suint256);
    assert!(
        matches!(a_audit.state, HandleState::Ready { .. }),
        "audit must preserve the original Ready state of the tombstoned source"
    );

    let d_audit = core
        .handle_record_for_audit(&d)
        .expect("audit must surface cascade-tombstoned derived");
    assert_eq!(
        d_audit.event_ref, d_event,
        "cascade must not rewrite the descendant's original ChainEventRef"
    );
    assert_eq!(d_audit.state, HandleState::Pending);

    assert!(
        core.canonical_handle(&b).is_some(),
        "sibling source untouched by the cascade must remain canonical"
    );
    assert!(
        core.canonical_handle(&other).is_some(),
        "unrelated source untouched by the cascade must remain canonical"
    );

    let post = core.resolution_readiness();
    assert!(
        find_readiness(&post, &c).is_none(),
        "tombstoned c must not appear in Resolution Readiness"
    );
    assert!(
        find_readiness(&post, &d).is_none(),
        "cascade-tombstoned d must not appear in Resolution Readiness"
    );
}

// ---------------------------------------------------------------------------
// Scenario G — One graph exercising every acceptance theme in sequence
//
// This is the "scenario tests combine ... in one Handle Graph" acceptance
// criterion read literally: a single HandleGraphCore instance moves through
// ingestion, validation, idempotent replay, Resolution Readiness, Orphan
// Discard, and canonical/audit divergence without resetting state in between.
// ---------------------------------------------------------------------------

#[test]
fn full_graph_lifecycle_combines_ingestion_validation_readiness_and_orphan_discard() {
    let mut core = HandleGraphCore::new();

    // Two Imported sources and one Plaintext source seed the graph.
    let imported_a = handle_key(1, 7, 1);
    let imported_b = handle_key(1, 7, 2);
    let plaintext_source = handle_key(1, 7, 3);
    let imported_a_event = chain_event_ref(1, 1, 1);
    let imported_a_ciphertext = SystemCiphertextV1(vec![0xA1]);
    let imported_a_receipt = MaterializationReceipt(vec![0xA2]);
    let _ = expect_recorded(core.apply_chain_event(imported_event(
        imported_a,
        HandleType::Suint256,
        imported_a_event,
        imported_a_ciphertext.clone(),
        imported_a_receipt,
    )));
    seed_imported(
        &mut core,
        imported_b,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    let _ = expect_recorded(core.apply_chain_event(plaintext_event(
        plaintext_source,
        HandleType::Sbool,
        chain_event_ref(1, 1, 3),
        PublicPlaintextValue(vec![0x01]),
    )));

    // Valid derived operation (Add) — should reach Resolution Readiness.
    let valid_add = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        valid_add,
        OperationCode::Add,
        HandleType::Suint256,
        vec![imported_a, imported_b],
        chain_event_ref(1, 2, 1),
    )));

    // Invalid derived operation (wrong arity) — should be Failed but still
    // canonical and visible. Routed through `imported_b` so the later
    // Orphan Discard of `imported_a` does not cascade-tombstone this record;
    // that lets us check the Failed-but-canonical query path survives an
    // unrelated discard.
    let invalid_arity = handle_key(1, 7, 11);
    let _ = expect_recorded(core.apply_chain_event(derived_event(
        invalid_arity,
        OperationCode::Add,
        HandleType::Suint256,
        vec![imported_b],
        chain_event_ref(1, 2, 2),
    )));

    // Idempotent replay of the valid Add — must not change anything.
    let replay = core.apply_chain_event(derived_event(
        valid_add,
        OperationCode::Add,
        HandleType::Suint256,
        vec![imported_a, imported_b],
        chain_event_ref(1, 2, 1),
    ));
    assert!(matches!(replay, IngestionOutcome::Idempotent));

    // Unknown Handle Key check on the canonical path.
    assert!(core.canonical_handle(&handle_key(1, 7, 200)).is_none());

    let ready_before_discard = core.resolution_readiness();
    let entry = find_readiness(&ready_before_discard, &valid_add)
        .expect("valid Add derived must be reported ready");
    assert_eq!(entry.input_handle_keys, vec![imported_a, imported_b]);
    assert_eq!(
        entry.input_system_ciphertexts[0],
        imported_a_ciphertext,
        "Resolution Readiness must echo the original imported ciphertext"
    );
    assert!(
        find_readiness(&ready_before_discard, &invalid_arity).is_none(),
        "Failed derived must never reach Resolution Readiness"
    );

    // Tombstone imported_a — cascades to valid_add but not to the Failed
    // wrong-arity record (it has no input lineage through a known input
    // handle: the Failed state never created a graph edge that resolves).
    let discard = core.apply_orphan_discard(&[imported_a_event]);
    assert_eq!(discard.directly_tombstoned, vec![imported_a]);
    let cascaded: std::collections::HashSet<HandleKey> =
        discard.cascade_tombstoned.iter().copied().collect();
    assert!(
        cascaded.contains(&valid_add),
        "valid Add must be cascade-tombstoned when its imported input is discarded"
    );

    // After discard: canonical query hides the tombstoned records but the
    // audit query still surfaces them.
    assert!(core.canonical_handle(&imported_a).is_none());
    assert!(core.canonical_handle(&valid_add).is_none());
    let imported_audit = core
        .handle_record_for_audit(&imported_a)
        .expect("audit must surface tombstoned imported source");
    assert!(imported_audit.is_tombstoned);
    let derived_audit = core
        .handle_record_for_audit(&valid_add)
        .expect("audit must surface cascade-tombstoned derived");
    assert!(derived_audit.is_tombstoned);
    assert_eq!(derived_audit.state, HandleState::Pending);

    // Records untouched by the cascade keep their canonical visibility.
    assert!(core.canonical_handle(&imported_b).is_some());
    assert!(core.canonical_handle(&plaintext_source).is_some());

    // Resolution Readiness now excludes both the tombstoned valid_add and
    // the still-Failed invalid_arity.
    let ready_after_discard = core.resolution_readiness();
    assert!(find_readiness(&ready_after_discard, &valid_add).is_none());
    assert!(find_readiness(&ready_after_discard, &invalid_arity).is_none());

    // The wrong-arity Failed record was not tombstoned by the discard above;
    // the canonical query must still surface its Failed state for auditing
    // by the Internal Coordinator API.
    let failed_canonical = core
        .canonical_handle(&invalid_arity)
        .expect("Failed-but-canonical record must remain visible on canonical query");
    assert!(matches!(failed_canonical.state, HandleState::Failed { .. }));
}

// ---------------------------------------------------------------------------
// Helpers
//
// These helpers are intentionally limited to assembling ChainEvent fixtures
// and reading observable outputs. They never reach inside HandleGraphCore.
// ---------------------------------------------------------------------------

fn expect_recorded(outcome: IngestionOutcome) -> HandleRecord {
    match outcome {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected Recorded, got {:?}", other),
    }
}

fn seed_imported(
    core: &mut HandleGraphCore,
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
) {
    let _ = expect_recorded(core.apply_chain_event(imported_event(
        handle_key,
        handle_type,
        event_ref,
        SystemCiphertextV1(vec![0x01]),
        MaterializationReceipt(vec![0x02]),
    )));
}

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
    materialization_receipt: MaterializationReceipt,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        handle_type,
        system_ciphertext,
        materialization_receipt,
        event_ref,
    })
}

fn plaintext_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    public_value: PublicPlaintextValue,
) -> ChainEvent {
    ChainEvent::PlaintextHandle(PlaintextHandle {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        handle_type,
        public_value,
        event_ref,
    })
}

fn derived_event(
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    event_ref: ChainEventRef,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref,
    })
}

fn canonical_state(core: &HandleGraphCore, handle_key: &HandleKey) -> Option<HandleState> {
    core.canonical_handle(handle_key)
        .map(|record| record.state.clone())
}

fn ready_system_ciphertext(
    core: &HandleGraphCore,
    handle_key: &HandleKey,
) -> Option<SystemCiphertextV1> {
    match core.canonical_handle(handle_key)?.state {
        HandleState::Ready {
            ref system_ciphertext,
            ..
        } => Some(system_ciphertext.clone()),
        _ => None,
    }
}

fn find_readiness<'a>(
    ready: &'a [ResolutionReadiness],
    handle_key: &HandleKey,
) -> Option<&'a ResolutionReadiness> {
    ready.iter().find(|entry| entry.handle_key == *handle_key)
}

fn assert_no_derived_is_ready(core: &HandleGraphCore, derived_keys: &[HandleKey]) {
    for key in derived_keys {
        let state = canonical_state(core, key)
            .expect("derived handle must remain canonical to assert non-Ready");
        assert!(
            !matches!(state, HandleState::Ready { .. }),
            "Derived Handle {:?} must not become Ready in this PRD, got {:?}",
            key,
            state,
        );
    }
}

fn handle_key(chain_id: u64, contract_seed: u8, handle_seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress([contract_seed; 20]),
        handle_id: HandleId(bytes32(handle_seed)),
    }
}

fn chain_event_ref(chain_id: u64, block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(chain_id),
        block_number,
        block_hash: bytes32(11),
        tx_hash: bytes32(12),
        log_index,
    }
}

fn bytes32(seed: u8) -> [u8; 32] {
    [seed; 32]
}
