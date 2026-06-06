//! Coprocessor Host lifecycle and readiness tests.
//!
//! These tests exercise the host through its public interface: configuration
//! loading, lifecycle transitions, readiness reporting, dependency seam
//! signalling, and Handle Graph Core ownership. They never reach an HTTP
//! server, a chain RPC, MPC, or the Enclave runtime — those seams are
//! deliberately unwired in this slice.

use coprocessor_ciphertext_binding as cbinding;
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DomainId, HandleId, HandleKey, HandleType,
    ImportedHandle, IngestionOutcome, PlaintextHandle, PublicPlaintextValue, SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, DependencyName, HostConfig, HostConfigError, HostStartError, LifecycleState,
    Readiness, RetryPolicy,
};

#[test]
fn host_starts_with_local_development_config_and_loads_handle_graph_core() {
    let config = HostConfig::for_local_development();
    let mut host = CoprocessorHost::new(config.clone());

    assert_eq!(host.lifecycle(), LifecycleState::NotStarted);
    assert_eq!(host.readiness(), Readiness::NotStarted);

    host.start().expect("local-development config must start");

    assert_eq!(host.lifecycle(), LifecycleState::Running);
    assert_eq!(host.config(), &config);
    // HandleGraphCore is owned by the host and observable through its public
    // canonical-query interface; before any ingestion, an arbitrary key is
    // unknown.
    assert!(host
        .handle_graph_core()
        .canonical_handle(&sample_handle_key())
        .is_none());
}

#[test]
fn host_config_default_is_local_development_config() {
    assert_eq!(HostConfig::default(), HostConfig::for_local_development());
}

#[test]
fn host_readiness_distinguishes_configuration_loaded_from_all_dependencies_ready() {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();

    match host.readiness() {
        Readiness::ConfigurationLoaded { unavailable } => {
            // No dependency seams are wired in this slice, so every named
            // dependency must show up as unavailable.
            assert_eq!(
                unavailable,
                vec![
                    DependencyName::SymVmEventSurface,
                    DependencyName::Mpc,
                    DependencyName::Enclave,
                ],
            );
        }
        other => panic!("expected ConfigurationLoaded, got {other:?}"),
    }

    host.mark_dependency_available(DependencyName::SymVmEventSurface);
    host.mark_dependency_available(DependencyName::Mpc);
    host.mark_dependency_available(DependencyName::Enclave);
    assert_eq!(host.readiness(), Readiness::Ready);

    host.mark_dependency_unavailable(DependencyName::Mpc);
    match host.readiness() {
        Readiness::ConfigurationLoaded { unavailable } => {
            assert_eq!(unavailable, vec![DependencyName::Mpc]);
        }
        other => panic!("expected ConfigurationLoaded after dep loss, got {other:?}"),
    }
}

#[test]
fn host_rejects_invalid_configuration_before_starting() {
    let invalid = HostConfig {
        deployment_label: "   ".to_string(),
        ..HostConfig::for_local_development()
    };
    let mut host = CoprocessorHost::new(invalid);

    match host.start() {
        Err(HostStartError::InvalidConfig(HostConfigError::EmptyDeploymentLabel)) => {}
        other => panic!("expected EmptyDeploymentLabel, got {other:?}"),
    }

    assert_eq!(host.lifecycle(), LifecycleState::NotStarted);
    assert_eq!(host.readiness(), Readiness::NotStarted);
}

#[test]
fn host_shuts_down_cleanly_and_reports_shutdown_readiness() {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host.shutdown();

    assert_eq!(host.lifecycle(), LifecycleState::ShutDown);
    assert_eq!(host.readiness(), Readiness::ShutDown);

    // Restarting a shut-down host is an error, not a silent reopen.
    match host.start() {
        Err(HostStartError::AlreadyShutDown) => {}
        other => panic!("expected AlreadyShutDown, got {other:?}"),
    }
}

#[test]
fn host_start_is_idempotent_within_a_single_running_phase() {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host.start().unwrap();
    assert_eq!(host.lifecycle(), LifecycleState::Running);
}

#[test]
fn host_owns_handle_graph_core_and_routes_chain_events_through_it() {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();

    let imported = ImportedHandle {
        domain_id: DomainId([9u8; 32]),
        handle_key: sample_handle_key(),
        handle_type: HandleType::Suint256,
        system_ciphertext: SystemCiphertextV1(vec![0xAA]),
        event_ref: ChainEventRef {
            chain_id: ChainId(1),
            block_number: 100,
            block_hash: [0u8; 32],
            tx_hash: [0u8; 32],
            log_index: 0,
        },
    };
    let outcome = host
        .handle_graph_core_mut()
        .apply_chain_event(ChainEvent::ImportedHandle(imported));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));

    let record = host
        .handle_graph_core()
        .canonical_handle(&sample_handle_key())
        .expect("ingested handle must be canonical");
    assert_eq!(record.handle_type, HandleType::Suint256);
}

#[test]
fn validate_config_accepts_local_development_and_rejects_empty_label() {
    CoprocessorHost::validate_config(&HostConfig::for_local_development()).unwrap();
    let err = CoprocessorHost::validate_config(&HostConfig {
        deployment_label: String::new(),
        ..HostConfig::for_local_development()
    })
    .unwrap_err();
    assert_eq!(err, HostConfigError::EmptyDeploymentLabel);
}

#[test]
fn validate_config_rejects_zero_resolution_attempts() {
    let err = CoprocessorHost::validate_config(&HostConfig {
        deployment_label: "test".to_string(),
        retry_policy: RetryPolicy { max_attempts: 0 },
        ..HostConfig::for_local_development()
    })
    .unwrap_err();

    assert_eq!(err, HostConfigError::RetryPolicyRequiresAttempt);
}

#[test]
fn plaintext_handle_materialization_uses_configured_active_mpc_key_id() {
    let config = HostConfig::for_local_development();
    let expected_key_id = config.mpc.public_config.key_id;
    let mut host = CoprocessorHost::new(config);
    host.start().unwrap();

    let handle_key = sample_handle_key();
    let outcome = host
        .handle_graph_core_mut()
        .apply_chain_event(ChainEvent::PlaintextHandle(PlaintextHandle {
            domain_id: DomainId([0xAB; 32]),
            handle_key,
            handle_type: HandleType::Suint256,
            public_value: PublicPlaintextValue(vec![0x10, 0x20, 0x30]),
            event_ref: ChainEventRef {
                chain_id: handle_key.chain_id,
                block_number: 101,
                block_hash: [0x11; 32],
                tx_hash: [0x22; 32],
                log_index: 1,
            },
        }));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));

    let record = host
        .handle_graph_core()
        .canonical_handle(&handle_key)
        .expect("plaintext handle must be recorded");
    let ready_ciphertext = match &record.state {
        coprocessor_handle_graph_core::HandleState::Ready {
            system_ciphertext, ..
        } => system_ciphertext,
        other => panic!("expected Ready state, got {other:?}"),
    };
    let decoded = cbinding::SystemCiphertextV1::decode(&ready_ciphertext.0)
        .expect("materialized ciphertext must decode");
    assert_eq!(
        decoded.key_id, expected_key_id,
        "plaintext materializer must bind the host-configured active MPC key id"
    );
}

#[test]
fn validate_config_rejects_mpc_and_enclave_measurement_mismatch() {
    let mut config = HostConfig::for_local_development();
    config.mpc.public_config.approved_enclave_measurement = cbinding::AttestationDigest([0x99; 32]);

    let err = CoprocessorHost::validate_config(&config).unwrap_err();
    assert!(matches!(
        err,
        HostConfigError::MpcEnclaveMeasurementMismatch { .. }
    ));
}

fn sample_handle_key() -> HandleKey {
    HandleKey {
        chain_id: ChainId(1),
        contract_address: ContractAddress([0xC0u8; 20]),
        handle_id: HandleId([0x42u8; 32]),
    }
}
